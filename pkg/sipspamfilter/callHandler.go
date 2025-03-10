package sipspamfilter

import (
	"fmt"
	"strings"
	"time"

	"github.com/emiago/diago"
	"github.com/lithammer/shortuuid"
)

func (cfg *spamFilter) callHandler(inDialog *diago.DialogServerSession) {
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
	time.Sleep(cfg.config.Spam.TryToAnswerDelay.ToDuration())
	log.Debug("Trying")
	err := inDialog.Progress()
	if err != nil {
		log.Error("Progress failed: %v", err)
		return
	}

	log.Debug("Answer-Sleeping")
	time.Sleep(cfg.config.Spam.AnswerDelay.ToDuration())

	log.Debug("Answering")
	err = inDialog.Answer()
	if err != nil {
		log.Error("Answer failed: %v", err)
		return
	}

	log.Debug("Hangup-Sleeping")
	time.Sleep(cfg.config.Spam.HangupDelay.ToDuration())

	log.Debug("Dropping call")
	inDialog.Close()

	log.Info("Done")
}

func (cfg *spamFilter) isSpam(callerID string) (matchedFileName *string, matchedLineNo int, comment *string) {
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

func (cfg *spamFilter) convertToInternational(callerID string) string {
	// + is good
	if strings.HasPrefix(callerID, "+") {
		return callerID
	}

	// 00 - replace with +
	if strings.HasPrefix(callerID, "00") {
		return "+" + callerID[2:]
	}

	// if it starts from country code from config, add a plus
	if strings.HasPrefix(callerID, cfg.config.CountryCode) {
		return "+" + callerID
	}

	// if it starts with a single zero, replace it with a +countryCode
	if strings.HasPrefix(callerID, "0") {
		return "+" + cfg.config.CountryCode + callerID[1:]
	}

	// all other cases, just add a + and country code
	return "+" + cfg.config.CountryCode + callerID
}
