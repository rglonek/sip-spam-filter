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
	"github.com/fsnotify/fsnotify"
	"github.com/lithammer/shortuuid"
	"gopkg.in/yaml.v2"
)

type SpamFilter struct {
	LocalAddr        string               `json:"local_addr" yaml:"local_addr" default:"0.0.0.0:0"`
	SIP              SpamFilterSip        `json:"sip" yaml:"sip"`
	Spam             SpamFilterSpam       `json:"spam" yaml:"spam"`
	blacklistNumbers map[string]blacklist // number -> blacklist
	blacklistLock    sync.RWMutex         // if we are reloading, we lock, if we are reading, we rlock
	parserLock       sync.Mutex           // only one parser at a time, all others will be blocked and queued
}

type SpamFilterSip struct {
	User     string `json:"user" yaml:"user"`
	Password string `json:"password" yaml:"password"`
	Host     string `json:"host" yaml:"host"`
	Port     int    `json:"port" yaml:"port"`
}

type SpamFilterSpam struct {
	BlacklistPaths []string `json:"blacklist_paths" yaml:"blacklist_paths"`
	SleepSeconds   int      `json:"sleep_seconds" yaml:"sleep_seconds"`
	UseInotify     bool     `json:"use_inotify" yaml:"use_inotify"`
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
	err = cfg.Main()
	if err != nil {
		log.Fatal(err)
	}
}

func (cfg *SpamFilter) Main() error {
	log.Print("Parsing blacklists")
	err := cfg.parseBlacklist()
	if err != nil {
		return err
	}

	log.Print("Creating new userAgent")
	ua, err := sipgo.NewUA()
	if err != nil {
		return err
	}

	log.Print("Creating new client")
	client, err := sipgo.NewClient(ua, sipgo.WithClientAddr(cfg.LocalAddr))
	if err != nil {
		return err
	}

	log.Print("Setting up OS signal handlers")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Print("Received interrupt signal, shutting down")
		client.Close()
		ua.Close()
		os.Exit(0)
	}()
	go func() {
		sighupChan := make(chan os.Signal, 1)
		signal.Notify(sighupChan, syscall.SIGHUP)
		for {
			<-sighupChan
			log.Print("Received SIGHUP signal, reloading blacklists")
			if err := cfg.parseBlacklist(); err != nil {
				log.Printf("Error reloading blacklists: %v", err)
			} else {
				log.Print("Blacklists reloaded")
			}
		}
	}()

	if cfg.Spam.UseInotify {
		log.Print("Setting up inotify for blacklist files")
		err = cfg.setupInotify()
		if err != nil {
			return fmt.Errorf("error setting up inotify: %v", err)
		}
	}

	log.Print("Creating new call handler")
	dg := diago.NewDiago(ua, diago.WithClient(client))

	log.Print("Starting call handler")
	go func() {
		ctx := context.Background()
		err := dg.Serve(ctx, cfg.callHandler)
		if err != nil {
			log.Printf("Serve failed: %v", err)
		}
	}()

	log.Print("Registering with SIP server")
	err = dg.Register(context.TODO(), sip.Uri{
		Scheme:   "sip",
		User:     cfg.SIP.User,
		Password: cfg.SIP.Password,
		Host:     cfg.SIP.Host,
		Port:     cfg.SIP.Port,
	}, diago.RegisterOptions{
		Username: cfg.SIP.User,
		Password: cfg.SIP.Password,
	})
	if err != nil {
		return err
	}
	log.Print("Exiting")
	return nil
}

func (cfg *SpamFilter) callHandler(inDialog *diago.DialogServerSession) {
	from := inDialog.InviteRequest.From()
	if from == nil {
		log.Print("Incoming call: From is nil, skipping")
		return
	}
	callerID := from.Address.User
	if callerID == "" {
		log.Print("Incoming call: Caller ID is empty, skipping")
		return
	}

	log := log.New(os.Stderr, fmt.Sprintf("[TID=%s] [CID=%s] ", shortuuid.New(), callerID), log.LstdFlags)

	var blacklistFile *string
	var blacklistLineNo int
	var blackListLine *string
	if blacklistFile, blacklistLineNo, blackListLine = cfg.isSpam(callerID); blacklistFile == nil {
		log.Printf("Not on any blacklist, skipping")
		return
	}

	log.Printf("Caller on blacklist file=%s line=%d: %s", *blacklistFile, blacklistLineNo, *blackListLine)

	log.Printf("Trying")
	err := inDialog.Progress()
	if err != nil {
		log.Printf("Progress failed: %v", err)
		return
	}
	log.Printf("Answering")
	err = inDialog.Answer()
	if err != nil {
		log.Printf("Answer failed: %v", err)
		return
	}

	log.Print("Sleeping")
	time.Sleep(time.Second * time.Duration(cfg.Spam.SleepSeconds))

	log.Print("Dropping call")
	inDialog.Close()

	log.Print("Done")
}

func (cfg *SpamFilter) setupInotify() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	for _, path := range cfg.Spam.BlacklistPaths {
		err = watcher.Add(path)
		if err != nil {
			return err
		}
	}
	go func() {
		for event := range watcher.Events {
			// Check for Write, Create and Remove operations
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove) != 0 {
				log.Printf("Blacklist file %s has been modified/created/removed, reloading", event.Name)
				err := cfg.parseBlacklist()
				if err != nil {
					log.Printf("Error reloading blacklists: %v", err)
				} else {
					log.Print("Blacklists reloaded")
				}
			}
		}
	}()
	return nil
}

func (cfg *SpamFilter) parseBlacklist() error {
	cfg.parserLock.Lock()
	defer cfg.parserLock.Unlock()
	newList := make(map[string]blacklist)
	for _, path := range cfg.Spam.BlacklistPaths {
		fileInfo, err := os.Stat(path)
		if err != nil {
			log.Printf("Warning: Could not access path %s: %v", path, err)
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
						log.Printf("Warning: Error parsing file %s: %v", filePath, err)
					}
				}
				return nil
			})
			if err != nil {
				log.Printf("Warning: Error walking directory %s: %v", path, err)
			}
		} else {
			// Handle single file
			if err := cfg.parseFile(path, newList); err != nil {
				log.Printf("Warning: Error parsing file %s: %v", path, err)
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
			log.Printf("Warning: Number in file %s line %d does not start with +: %s", filePath, lineNo, line)
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
	callerID = cfg.convertToInternational(callerID)
	cfg.blacklistLock.RLock()
	defer cfg.blacklistLock.RUnlock()
	blacklist, ok := cfg.blacklistNumbers[callerID]
	if !ok {
		return nil, 0, nil
	}
	return &blacklist.fileName, blacklist.fileLineNo, &blacklist.line
}

func (cfg *SpamFilter) convertToInternational(callerID string) string {
	// TODO: Implement - convert callerID to international standard, using a + prefix
	return callerID
}
