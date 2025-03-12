package sipspamfilter

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/rglonek/diago"
	"github.com/rglonek/logger"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
)

type spamFilter struct {
	config                 *SpamFilterConfig
	blacklistNumbers       []*blacklist
	blacklistLock          sync.RWMutex // if we are reloading, we lock, if we are reading, we rlock
	parserLock             sync.Mutex   // only one parser at a time, all others will be blocked and queued
	log                    *logger.Logger
	auditBlockedNumbers    *os.File
	auditBlockedNumbersCSV *csv.Writer
	auditAllowedNumbers    *os.File
	auditAllowedNumbersCSV *csv.Writer
	auditFileSIGHUPLock    sync.RWMutex
	stats                  *stats
}

type blacklist struct {
	fileName string
	numbers  map[string]blacklistNumber
}

type blacklistNumber struct {
	lineNumber int
	comment    string
}

func Run(config *SpamFilterConfig, log *logger.Logger) error {
	// if config is nil, return an error
	if config == nil {
		return fmt.Errorf("config is nil")
	}

	// create a new spamFilter
	cfg := &spamFilter{
		config: config,
	}

	// initialize the logger
	cfg.initSetLogger(log)

	// patch zerolog to use the logger
	cfg.initPatchZerolog()

	// initialize the stats system
	cfg.initStats()

	// parse the blacklists
	log.Info("Parsing blacklists")
	err := cfg.parseBlacklist()
	if err != nil {
		return err
	}

	// open the audit files
	log.Info("Opening audit files")
	err = cfg.reopenAuditFiles()
	if err != nil {
		return err
	}

	// create a new sip userAgent
	log.Info("Creating new userAgent")
	ua, err := sipgo.NewUA(sipgo.WithUserAgent("spamfilter"))
	if err != nil {
		return err
	}

	// create a new sip client
	log.Info("Creating new client")
	client, err := sipgo.NewClient(ua, sipgo.WithClientAddr(cfg.config.LocalAddr))
	if err != nil {
		return err
	}

	// initialize the signal handlers
	exiter := cfg.initSignalHandlers(client, ua)

	// create a new call handler
	log.Info("Creating new call handler")
	tran, err := cfg.initTransport()
	if err != nil {
		return err
	}
	dg := diago.NewDiago(ua, diago.WithClient(client), diago.WithTransport(*tran))

	// start the call handler
	log.Info("Starting call handler")
	go func() {
		ctx := context.Background()
		err := dg.Serve(ctx, cfg.callHandler)
		if err != nil {
			log.Critical("Serve failed: %v", err)
		}
	}()

	// register with the SIP server
	go func() {
		log.Info("Registering with SIP server")
		err = dg.Register(context.TODO(), sip.Uri{
			Scheme:    "sip",
			User:      cfg.config.SIP.User,
			Password:  string(cfg.config.SIP.Password),
			Host:      cfg.config.SIP.Host,
			Port:      cfg.config.SIP.Port,
			UriParams: sip.NewParams().Add("transport", tran.Transport),
		}, diago.RegisterOptions{
			Username: cfg.config.SIP.User,
			Password: string(cfg.config.SIP.Password),
			Expiry:   cfg.config.SIP.Expiry.ToDuration(),
			ExtraHeaders: []sip.Header{
				sip.NewHeader("User-Agent", cfg.config.SIP.UserAgent),
			},
		})
		if err != nil {
			exiter <- err
		}
	}()
	err = <-exiter
	if err == nil {
		log.Info("All connections closed, exiting")
	}
	return err
}

func (cfg *spamFilter) initSetLogger(log *logger.Logger) {
	if log == nil {
		log = logger.NewLogger()
		log.SetLogLevel(logger.LogLevel(cfg.config.LogLevel))
		log.MillisecondLogging(true)
	}
	cfg.log = log
}

func (cfg *spamFilter) initPatchZerolog() {
	r, w, err := os.Pipe()
	if err != nil {
		cfg.log.Critical(err.Error())
	}
	zlog.Logger = zlog.Logger.Output(w)
	go func() {
		scanner := bufio.NewScanner(r)
		siplog := cfg.log.WithPrefix("SIP: ")
		unknownlog := cfg.log.WithPrefix("UNKNOWN: ")
		for scanner.Scan() {
			text := strings.TrimSuffix(scanner.Text(), "\n")
			var test struct {
				Level string `json:"level"`
			}
			err := json.Unmarshal([]byte(text), &test)
			if err != nil {
				unknownlog.Info(text)
				continue
			}
			switch test.Level {
			case zerolog.DebugLevel.String():
				siplog.Debug(text)
			case zerolog.InfoLevel.String():
				siplog.Info(text)
			case zerolog.WarnLevel.String():
				siplog.Warn(text)
			case zerolog.ErrorLevel.String():
				siplog.Error(text)
			case zerolog.FatalLevel.String():
				siplog.Critical(text)
			case zerolog.PanicLevel.String():
				siplog.Critical(text)
			case zerolog.TraceLevel.String():
				siplog.Detail(text)
			default:
				unknownlog.Info(text)
			}
		}
	}()
}

func (cfg *spamFilter) initStats() {
	cfg.stats = &stats{}
	go func() {
		for {
			time.Sleep(time.Second * 10)
			cfg.stats.print(cfg.log)
		}
	}()
}

func (cfg *spamFilter) initSignalHandlers(client *sipgo.Client, ua *sipgo.UserAgent) (exiter chan error) {
	cfg.log.Info("Setting up OS signal handlers")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	exiter = make(chan error, 1)
	go func() {
		<-sigChan
		cfg.log.Info("Received interrupt signal, shutting down")
		client.Close()
		ua.Close()
		cfg.closeAuditFiles(true)
		exiter <- nil
	}()
	go func() {
		sigUsr1Chan := make(chan os.Signal, 1)
		signal.Notify(sigUsr1Chan, syscall.SIGUSR1)
		for {
			<-sigUsr1Chan
			cfg.log.Info("SIGUSR1: Reloading blacklists")
			if err := cfg.parseBlacklist(); err != nil {
				cfg.log.Error("Error reloading blacklists: %v", err)
			} else {
				cfg.log.Info("SIGUSR1: Blacklists reloaded")
			}
		}
	}()
	go func() {
		sighupChan := make(chan os.Signal, 1)
		signal.Notify(sighupChan, syscall.SIGHUP)
		for {
			<-sighupChan
			cfg.log.Info("SIGHUP: Reopening audit files")
			if err := cfg.reopenAuditFiles(); err != nil {
				cfg.log.Error("Error reopening audit files: %v", err)
			} else {
				cfg.log.Info("SIGHUP: Audit files reopened")
			}
		}
	}()
	return exiter
}

func (cfg *spamFilter) initTransport() (tr *diago.Transport, err error) {
	tranData := strings.Split(cfg.config.LocalAddrInbound, ":")
	if len(tranData) != 3 {
		return nil, fmt.Errorf("invalid inbound transport: %s, should be <transport>:<host>:<port>", cfg.config.LocalAddrInbound)
	}
	tranData[0] = strings.ToLower(tranData[0])
	switch tranData[0] {
	case "udp", "tcp":
	default:
		return nil, fmt.Errorf("invalid inbound transport: %s", tranData[0])
	}
	bindPort, err := strconv.Atoi(tranData[2])
	if err != nil {
		return nil, fmt.Errorf("invalid inbound port: %s", tranData[2])
	}
	if net.ParseIP(tranData[1]) == nil {
		return nil, fmt.Errorf("invalid inbound host: %s", tranData[1])
	}
	tran := diago.Transport{
		Transport: tranData[0],
		BindHost:  tranData[1],
		BindPort:  bindPort,
	}
	return &tran, nil
}
