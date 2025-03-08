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
	zlog "github.com/rs/zerolog/log"
	"gopkg.in/yaml.v2"
)

type SpamFilter struct {
	LogLevel            int                  `json:"log_level" yaml:"log_level" default:"4"`
	LocalAddr           string               `json:"local_addr" yaml:"local_addr" default:"0.0.0.0:0"`
	CountryCode         string               `json:"country_code" yaml:"country_code" default:"44"`
	SIP                 SpamFilterSip        `json:"sip" yaml:"sip"`
	AuditFiles          SpamFilterAuditFiles `json:"audit_files" yaml:"audit_files"`
	Spam                SpamFilterSpam       `json:"spam" yaml:"spam"`
	blacklistNumbers    []*blacklist
	blacklistLock       sync.RWMutex // if we are reloading, we lock, if we are reading, we rlock
	parserLock          sync.Mutex   // only one parser at a time, all others will be blocked and queued
	log                 *logger.Logger
	auditBlockedNumbers *os.File
	auditAllowedNumbers *os.File
	auditFileSIGHUPLock sync.RWMutex
	stats               *stats
}

type stats struct {
	lock            sync.RWMutex
	blockedCount    int
	allowedCount    int
	lookupTotalTime time.Duration
	oldCounts       int
}

func (s *stats) addBlocked(lookupTime time.Duration) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.blockedCount++
	s.lookupTotalTime += lookupTime
}

func (s *stats) addAllowed(lookupTime time.Duration) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.allowedCount++
	s.lookupTotalTime += lookupTime
}

func (s *stats) print(log *logger.Logger) {
	s.lock.Lock()
	allowedCount := s.allowedCount
	blockedCount := s.blockedCount
	lookupTotalTime := s.lookupTotalTime
	total := blockedCount + allowedCount
	if s.oldCounts == total {
		s.lock.Unlock()
		return
	}
	s.oldCounts = total
	s.lock.Unlock()
	avgLookupTime := time.Duration(0)
	if total > 0 {
		avgLookupTime = lookupTotalTime / time.Duration(total)
	}
	log.Info("Stats: blocked=%d allowed=%d averageLookupTime=%s", blockedCount, allowedCount, avgLookupTime)
}

type SpamFilterSip struct {
	User          string `json:"user" yaml:"user"`
	Password      string `json:"password" yaml:"password"`
	Host          string `json:"host" yaml:"host"`
	Port          int    `json:"port" yaml:"port"`
	ExpirySeconds int    `json:"expiry_seconds" yaml:"expiry_seconds" default:"500"`
}

type SpamFilterSpam struct {
	TryToAnswerDelayMs int      `json:"try_to_answer_delay_ms" yaml:"try_to_answer_delay_ms"`
	AnswerDelayMs      int      `json:"answer_delay_ms" yaml:"answer_delay_ms"`
	HangupDelayMs      int      `json:"hangup_delay_ms" yaml:"hangup_delay_ms"`
	BlacklistPaths     []string `json:"blacklist_paths" yaml:"blacklist_paths"`
}

type SpamFilterAuditFiles struct {
	BlockedNumbers string `json:"blocked_numbers" yaml:"blocked_numbers"`
	AllowedNumbers string `json:"allowed_numbers" yaml:"allowed_numbers"`
}

type blacklist struct {
	fileName string
	numbers  map[string]blacklistNumber
}

type blacklistNumber struct {
	lineNumber int
	comment    string
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

	// create a logger pipe and patch zerolog and os.Std* to use it
	r, w, err := os.Pipe()
	if err != nil {
		log.Critical(err.Error())
	}
	os.Stdout = w
	os.Stderr = w
	zlog.Logger = zlog.Logger.Output(w)
	go func() {
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			log.Detail(strings.TrimSuffix(scanner.Text(), "\n"))
		}
	}()

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
	cfg.stats = &stats{}
	log.Info("Parsing blacklists")
	err := cfg.parseBlacklist()
	if err != nil {
		return err
	}

	log.Info("Opening audit files")
	err = cfg.reopenAuditFiles()
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
		sigUsr1Chan := make(chan os.Signal, 1)
		signal.Notify(sigUsr1Chan, syscall.SIGUSR1)
		for {
			<-sigUsr1Chan
			log.Info("SIGUSR1: Reloading blacklists")
			if err := cfg.parseBlacklist(); err != nil {
				log.Error("Error reloading blacklists: %v", err)
			} else {
				log.Info("SIGUSR1: Blacklists reloaded")
			}
		}
	}()
	go func() {
		sighupChan := make(chan os.Signal, 1)
		signal.Notify(sighupChan, syscall.SIGHUP)
		for {
			<-sighupChan
			log.Info("SIGHUP: Reopening audit files")
			if err := cfg.reopenAuditFiles(); err != nil {
				log.Error("Error reopening audit files: %v", err)
			} else {
				log.Info("SIGHUP: Audit files reopened")
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

	go func() {
		for {
			time.Sleep(time.Second * 10)
			cfg.stats.print(log)
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
	var blacklistComment *string
	if blacklistFile, blacklistLineNo, blacklistComment = cfg.isSpam(newCallerID); blacklistFile == nil {
		log.Info("Not on any blacklist, skipping")
		cfg.auditLogAllowed(newCallerID)
		return
	}

	log.Info("Caller on blacklist file=%s line=%d comment=%s", *blacklistFile, blacklistLineNo, *blacklistComment)
	cfg.auditLogBlocked(newCallerID, *blacklistFile, blacklistLineNo)

	log.Debug("Try-Sleeping")
	time.Sleep(time.Millisecond * time.Duration(cfg.Spam.TryToAnswerDelayMs))
	log.Debug("Trying")
	err := inDialog.Progress()
	if err != nil {
		log.Error("Progress failed: %v", err)
		return
	}

	log.Debug("Answer-Sleeping")
	time.Sleep(time.Millisecond * time.Duration(cfg.Spam.AnswerDelayMs))

	log.Debug("Answering")
	err = inDialog.Answer()
	if err != nil {
		log.Error("Answer failed: %v", err)
		return
	}

	log.Debug("Hangup-Sleeping")
	time.Sleep(time.Millisecond * time.Duration(cfg.Spam.HangupDelayMs))

	log.Debug("Dropping call")
	inDialog.Close()

	log.Info("Done")
}

func (cfg *SpamFilter) parseBlacklist() error {
	cfg.parserLock.Lock()
	defer cfg.parserLock.Unlock()
	var newList []*blacklist
	for _, path := range cfg.Spam.BlacklistPaths {
		fileInfo, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("could not access path %s: %v", path, err)
		}

		if fileInfo.IsDir() {
			// Handle directory
			err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !info.IsDir() {
					bl, err := cfg.parseFile(filePath)
					if err != nil {
						return fmt.Errorf("error parsing file %s: %v", filePath, err)
					}
					newList = append(newList, bl)
				}
				return nil
			})
			if err != nil {
				return fmt.Errorf("error walking directory %s: %v", path, err)
			}
		} else {
			// Handle single file
			bl, err := cfg.parseFile(path)
			if err != nil {
				return fmt.Errorf("error parsing file %s: %v", path, err)
			}
			newList = append(newList, bl)
		}
	}

	cfg.blacklistLock.Lock()
	defer cfg.blacklistLock.Unlock()
	cfg.blacklistNumbers = newList
	return nil
}

// Helper function to parse individual files
func (cfg *SpamFilter) parseFile(filePath string) (*blacklist, error) {
	log := cfg.log.WithPrefix(fmt.Sprintf("parseFile: %s: ", filePath))
	newList := &blacklist{
		fileName: filePath,
		numbers:  make(map[string]blacklistNumber),
	}
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Strip comments from the line
		lineSplit := strings.Split(line, "#")
		line = strings.TrimRight(strings.TrimSpace(lineSplit[0]), "\n\r")
		if line == "" {
			continue
		}
		comment := ""
		if len(lineSplit) > 1 {
			comment = strings.TrimRight(strings.TrimSpace(lineSplit[1]), "\n\r")
		}

		// Check if number starts with +
		if !strings.HasPrefix(line, "+") {
			log.Warn("Number in file %s line %d does not start with +: %s", filePath, lineNo, line)
		}

		if val, ok := newList.numbers[line]; ok {
			log.Warn("Ignoring duplicate number on line number %d (first seen on line %d) in file %s", lineNo, val.lineNumber, filePath)
		} else {
			newList.numbers[line] = blacklistNumber{
				lineNumber: lineNo,
				comment:    comment,
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return newList, nil
}

func (cfg *SpamFilter) isSpam(callerID string) (matchedFileName *string, matchedLineNo int, comment *string) {
	start := time.Now()
	cfg.blacklistLock.RLock()
	defer cfg.blacklistLock.RUnlock()
	for _, blacklist := range cfg.blacklistNumbers {
		if val, ok := blacklist.numbers[callerID]; ok {
			fn := blacklist.fileName
			ln := val.lineNumber
			cm := val.comment
			cfg.stats.addBlocked(time.Since(start))
			return &fn, ln, &cm
		}
	}
	cfg.stats.addAllowed(time.Since(start))
	return nil, 0, nil
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

func (cfg *SpamFilter) reopenAuditFiles() error {
	var err error
	cfg.auditFileSIGHUPLock.Lock()
	defer cfg.auditFileSIGHUPLock.Unlock()
	if cfg.auditBlockedNumbers != nil {
		cfg.auditBlockedNumbers.Close()
	}
	if cfg.auditAllowedNumbers != nil {
		cfg.auditAllowedNumbers.Close()
	}
	if cfg.AuditFiles.BlockedNumbers != "" {
		cfg.auditBlockedNumbers, err = os.OpenFile(cfg.AuditFiles.BlockedNumbers, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return err
		}
	}
	if cfg.AuditFiles.AllowedNumbers != "" {
		cfg.auditAllowedNumbers, err = os.OpenFile(cfg.AuditFiles.AllowedNumbers, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return err
		}
	}
	return nil
}

func (cfg *SpamFilter) auditLogAllowed(number string) {
	cfg.auditFileSIGHUPLock.RLock()
	defer cfg.auditFileSIGHUPLock.RUnlock()
	if cfg.auditAllowedNumbers != nil {
		_, err := cfg.auditAllowedNumbers.WriteString(fmt.Sprintf("%s,%s\n", time.Now().Format(time.RFC3339), number))
		if err != nil {
			cfg.log.Error("Audit log: Error writing to audit allowed numbers: %v", err)
		}
	}
}

func (cfg *SpamFilter) auditLogBlocked(number string, fileName string, lineNo int) {
	cfg.auditFileSIGHUPLock.RLock()
	defer cfg.auditFileSIGHUPLock.RUnlock()
	if cfg.auditBlockedNumbers != nil {
		_, err := cfg.auditBlockedNumbers.WriteString(fmt.Sprintf("%s,%s,%s,%d\n", time.Now().Format(time.RFC3339), number, fileName, lineNo))
		if err != nil {
			cfg.log.Error("Audit log: Error writing to audit blocked numbers: %v", err)
		}
	}
}
