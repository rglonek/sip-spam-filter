package main

import (
	"flag"
	"log"
	"os"
	"sip-spam-filter/pkg/sipspamfilter"

	"github.com/creasty/defaults"
	"github.com/rglonek/logger"
	"gopkg.in/yaml.v3"
)

var version = "0.1"

func main() {
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
	err = yaml.Unmarshal(configData, config)
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
