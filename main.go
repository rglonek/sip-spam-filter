package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/emiago/diago"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/lithammer/shortuuid"
	"github.com/rglonek/logger"
	"gopkg.in/yaml.v2"
)

type SpamFilter struct {
	LogLevel         int                  `json:"log_level" yaml:"log_level" default:"4"`
	LocalAddr        string               `json:"local_addr" yaml:"local_addr" default:"0.0.0.0:0"`
	CountryCode      string               `json:"country_code" yaml:"country_code" default:"44"`
	SIP              SpamFilterSip        `json:"sip" yaml:"sip"`
	Spam             SpamFilterSpam       `json:"spam" yaml:"spam"`
	blacklistNumbers map[string]blacklist // number -> blacklist
	blacklistLock    sync.RWMutex         // if we are reloading, we lock, if we are reading, we rlock
	parserLock       sync.Mutex           // only one parser at a time, all others will be blocked and queued
	log              *logger.Logger
}

type SpamFilterSip struct {
	User          string `json:"user" yaml:"user"`
	Password      string `json:"password" yaml:"password"`
	Host          string `json:"host" yaml:"host"`
	Port          int    `json:"port" yaml:"port"`
	ExpirySeconds int    `json:"expiry_seconds" yaml:"expiry_seconds" default:"500"`
}

type SpamFilterSpam struct {
	SleepSeconds   int      `json:"sleep_seconds" yaml:"sleep_seconds"`
	BlacklistPaths []string `json:"blacklist_paths" yaml:"blacklist_paths"`
}

type blacklist struct {
	fileName   string
	fileLineNo int
	line       string
}

func main() {
	configPath := flag.String("config", "", "path to config file")
	flag.Parse()
	if *configPath == "" {
		log.Fatal("--config parameter is required")
	}
	cfg := &SpamFilter{}
	configData, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}
	err = yaml.Unmarshal(configData, cfg)
	if err != nil {
		log.Fatalf("Failed to parse config file: %v", err)
	}
	configYaml, err := yaml.Marshal(cfg)
	if err != nil {
		log.Fatalf("Failed to marshal config: %v", err)
	}
	log.Printf("Loaded config:\n%s", string(configYaml))

	log := logger.NewLogger()
	log.SetLogLevel(logger.LogLevel(cfg.LogLevel))
	log.MillisecondLogging(true)
	err = cfg.Main(log)
	if err != nil {
		log.Critical(err.Error())
	}
}

func (cfg *SpamFilter) Main(log *logger.Logger) error {
	if log == nil {
		log = logger.NewLogger()
		log.SetLogLevel(logger.LogLevel(cfg.LogLevel))
		log.MillisecondLogging(true)
	}
	cfg.log = log
	log.Info("Parsing blacklists")
	err := cfg.parseBlacklist()
	if err != nil {
		return err
	}

	log.Info("Creating new userAgent")
	ua, err := sipgo.NewUA()
	if err != nil {
		return err
	}

	log.Info("Creating new client")
	client, err := sipgo.NewClient(ua, sipgo.WithClientAddr(cfg.LocalAddr))
	if err != nil {
		return err
	}

	log.Info("Setting up OS signal handlers")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Info("Received interrupt signal, shutting down")
		client.Close()
		ua.Close()
		os.Exit(0)
	}()
	go func() {
		sighupChan := make(chan os.Signal, 1)
		signal.Notify(sighupChan, syscall.SIGUSR1)
		for {
			<-sighupChan
			log.Info("SIGUSR1: Reloading blacklists")
			if err := cfg.parseBlacklist(); err != nil {
				log.Error("Error reloading blacklists: %v", err)
			} else {
				log.Info("SIGUSR1: Blacklists reloaded")
			}
		}
	}()

	log.Info("Creating new call handler")
	dg := diago.NewDiago(ua, diago.WithClient(client))

	log.Info("Starting call handler")
	go func() {
		ctx := context.Background()
		err := dg.Serve(ctx, cfg.callHandler)
		if err != nil {
			log.Critical("Serve failed: %v", err)
		}
	}()

	log.Info("Registering with SIP server")
	err = dg.Register(context.TODO(), sip.Uri{
		Scheme:   "sip",
		User:     cfg.SIP.User,
		Password: cfg.SIP.Password,
		Host:     cfg.SIP.Host,
		Port:     cfg.SIP.Port,
	}, diago.RegisterOptions{
		Username: cfg.SIP.User,
		Password: cfg.SIP.Password,
		Expiry:   time.Duration(cfg.SIP.ExpirySeconds) * time.Second,
	})
	if err != nil {
		return err
	}
	log.Info("Exiting")
	return nil
}

func (cfg *SpamFilter) callHandler(inDialog *diago.DialogServerSession) {
	log := cfg.log.WithPrefix(fmt.Sprintf("[TID=%s] ", shortuuid.New()))
	from := inDialog.InviteRequest.From()
	if from == nil {
		log.Info("Incoming call: From is nil, skipping")
		return
	}
	callerID := from.Address.User
	if callerID == "" {
		log.Info("Incoming call: Caller ID is empty, skipping")
		return
	}

	newCallerID := cfg.convertToInternational(callerID)
	log = log.WithPrefix(fmt.Sprintf("[OCID=%s] [CID=%s] ", callerID, newCallerID))

	var blacklistFile *string
	var blacklistLineNo int
	var blackListLine *string
	if blacklistFile, blacklistLineNo, blackListLine = cfg.isSpam(newCallerID); blacklistFile == nil {
		log.Info("Not on any blacklist, skipping")
		return
	}

	log.Info("Caller on blacklist file=%s line=%d: %s", *blacklistFile, blacklistLineNo, *blackListLine)

	log.Debug("Trying")
	err := inDialog.Progress()
	if err != nil {
		log.Error("Progress failed: %v", err)
		return
	}
	log.Debug("Answering")
	err = inDialog.Answer()
	if err != nil {
		log.Error("Answer failed: %v", err)
		return
	}

	log.Debug("Sleeping")
	time.Sleep(time.Second * time.Duration(cfg.Spam.SleepSeconds))

	log.Debug("Dropping call")
	inDialog.Close()

	log.Info("Done")
}

func (cfg *SpamFilter) parseBlacklist() error {
	log := cfg.log.WithPrefix("parseBlacklist: ")
	cfg.parserLock.Lock()
	defer cfg.parserLock.Unlock()
	newList := make(map[string]blacklist)
	for _, path := range cfg.Spam.BlacklistPaths {
		fileInfo, err := os.Stat(path)
		if err != nil {
			log.Error("Could not access path %s: %v", path, err)
			continue
		}

		if fileInfo.IsDir() {
			// Handle directory
			err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !info.IsDir() {
					if err := cfg.parseFile(filePath, newList); err != nil {
						log.Error("Error parsing file %s: %v", filePath, err)
					}
				}
				return nil
			})
			if err != nil {
				log.Error("Error walking directory %s: %v", path, err)
			}
		} else {
			// Handle single file
			if err := cfg.parseFile(path, newList); err != nil {
				log.Error("Error parsing file %s: %v", path, err)
			}
		}
	}

	cfg.blacklistLock.Lock()
	defer cfg.blacklistLock.Unlock()
	cfg.blacklistNumbers = newList
	return nil
}

// Helper function to parse individual files
func (cfg *SpamFilter) parseFile(filePath string, newList map[string]blacklist) error {
	log := cfg.log.WithPrefix(fmt.Sprintf("parseFile: %s: ", filePath))
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		origLine := line

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Strip comments from the line
		if idx := strings.Index(line, "#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
			if line == "" {
				continue
			}
		}

		// Check if number starts with +
		if !strings.HasPrefix(line, "+") {
			log.Warn("Number in file %s line %d does not start with +: %s", filePath, lineNo, line)
		}

		newList[line] = blacklist{
			fileName:   filePath,
			fileLineNo: lineNo,
			line:       origLine,
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func (cfg *SpamFilter) isSpam(callerID string) (matchedFileName *string, matchedLineNo int, matchedLine *string) {
	cfg.blacklistLock.RLock()
	defer cfg.blacklistLock.RUnlock()
	blacklist, ok := cfg.blacklistNumbers[callerID]
	if !ok {
		return nil, 0, nil
	}
	fn := blacklist.fileName
	ln := blacklist.fileLineNo
	ml := blacklist.line
	return &fn, ln, &ml
}

func (cfg *SpamFilter) convertToInternational(callerID string) string {
	// + is good
	if strings.HasPrefix(callerID, "+") {
		return callerID
	}

	// 00 - replace with +
	if strings.HasPrefix(callerID, "00") {
		return "+" + callerID[2:]
	}

	// if it starts from country code from config, add a plus
	if strings.HasPrefix(callerID, cfg.CountryCode) {
		return "+" + callerID
	}

	// if it starts with a single zero, replace it with a +countryCode
	if strings.HasPrefix(callerID, "0") {
		return "+" + cfg.CountryCode + callerID[1:]
	}

	// all other cases, just add a + and country code
	return "+" + cfg.CountryCode + callerID
}
