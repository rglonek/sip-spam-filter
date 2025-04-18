package main

import (
	"bytes"
	"flag"
	"log"
	"os"
	"sip-spam-filter/pkg/sipspamfilter"
	"strings"

	_ "embed"

	"github.com/creasty/defaults"
	"github.com/rglonek/logger"
	"gopkg.in/yaml.v3"
)

//go:embed VERSION
var version string

func main() {
	version = strings.Trim(version, "\n\r\t ")
	log.Println("=-=-=-=-= SIP-SPAM-FILTER v" + version + " =-=-=-=-=")
	configPath := flag.String("config", "", "path to config file")
	flag.Parse()
	if *configPath == "" {
		log.Fatal("--config parameter is required")
	}
	config := &sipspamfilter.SpamFilterConfig{
		SIP: sipspamfilter.SpamFilterSip{
			UserAgent: "spam-filter/" + version,
		},
	}
	if err := defaults.Set(config); err != nil {
		log.Fatalf("Failed to set defaults: %v", err)
	}
	configData, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(configData))
	decoder.KnownFields(true)
	err = decoder.Decode(config)
	if err != nil {
		log.Fatalf("Failed to parse config file: %v", err)
	}

	configYaml, err := yaml.Marshal(config)
	if err != nil {
		log.Fatalf("Failed to marshal config: %v", err)
	}
	log.Printf("Loaded config:\n%s", string(configYaml))

	log := logger.NewLogger()
	log.SetLogLevel(logger.LogLevel(config.LogLevel))
	log.MillisecondLogging(true)

	err = sipspamfilter.Run(config, log)
	if err != nil {
		log.Critical(err.Error())
	}
}
