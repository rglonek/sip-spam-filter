package sipspamfilter

import (
	"fmt"
	"os"
	"time"
)

func (cfg *spamFilter) reopenAuditFiles() error {
	var err error
	cfg.auditFileSIGHUPLock.Lock()
	defer cfg.auditFileSIGHUPLock.Unlock()
	if cfg.auditBlockedNumbers != nil {
		cfg.auditBlockedNumbers.Close()
	}
	if cfg.auditAllowedNumbers != nil {
		cfg.auditAllowedNumbers.Close()
	}
	if cfg.config.AuditFiles.BlockedNumbers != "" {
		cfg.auditBlockedNumbers, err = os.OpenFile(cfg.config.AuditFiles.BlockedNumbers, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return err
		}
	}
	if cfg.config.AuditFiles.AllowedNumbers != "" {
		cfg.auditAllowedNumbers, err = os.OpenFile(cfg.config.AuditFiles.AllowedNumbers, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return err
		}
	}
	return nil
}

func (cfg *spamFilter) auditLogAllowed(number string) {
	cfg.auditFileSIGHUPLock.RLock()
	defer cfg.auditFileSIGHUPLock.RUnlock()
	if cfg.auditAllowedNumbers != nil {
		_, err := cfg.auditAllowedNumbers.WriteString(fmt.Sprintf("%s,%s\n", time.Now().Format(time.RFC3339), number))
		if err != nil {
			cfg.log.Error("Audit log: Error writing to audit allowed numbers: %v", err)
		}
	}
}

func (cfg *spamFilter) auditLogBlocked(number string, fileName string, lineNo int) {
	cfg.auditFileSIGHUPLock.RLock()
	defer cfg.auditFileSIGHUPLock.RUnlock()
	if cfg.auditBlockedNumbers != nil {
		_, err := cfg.auditBlockedNumbers.WriteString(fmt.Sprintf("%s,%s,%s,%d\n", time.Now().Format(time.RFC3339), number, fileName, lineNo))
		if err != nil {
			cfg.log.Error("Audit log: Error writing to audit blocked numbers: %v", err)
		}
	}
}
