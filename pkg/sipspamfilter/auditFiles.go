package sipspamfilter

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"time"
)

func (cfg *spamFilter) reopenAuditFiles() error {
	var err error
	cfg.auditFileSIGHUPLock.Lock()
	defer cfg.auditFileSIGHUPLock.Unlock()
	cfg.closeAuditFiles(false)
	if cfg.config.AuditFiles.BlockedNumbers != "" {
		cfg.auditBlockedNumbers, err = os.OpenFile(cfg.config.AuditFiles.BlockedNumbers, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			cfg.auditBlockedNumbers = nil
			return err
		}
		cfg.auditBlockedNumbersCSV = csv.NewWriter(cfg.auditBlockedNumbers)
		stat, err := cfg.auditBlockedNumbers.Stat()
		if err == nil && stat.Size() == 0 {
			err = writeCSV(cfg.auditBlockedNumbersCSV, []string{"timestamp", "number", "blocklist_file_name", "blocklist_file_line_number"})
			if err != nil {
				cfg.log.Error("Audit log: Error writing header to audit blocked numbers: %v", err)
			}
		}
	}
	if cfg.config.AuditFiles.AllowedNumbers != "" {
		cfg.auditAllowedNumbers, err = os.OpenFile(cfg.config.AuditFiles.AllowedNumbers, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			cfg.auditAllowedNumbers = nil
			return err
		}
		cfg.auditAllowedNumbersCSV = csv.NewWriter(cfg.auditAllowedNumbers)
		stat, err := cfg.auditAllowedNumbers.Stat()
		if err == nil && stat.Size() == 0 {
			err = writeCSV(cfg.auditAllowedNumbersCSV, []string{"timestamp", "number"})
			if err != nil {
				cfg.log.Error("Audit log: Error writing header to audit allowed numbers: %v", err)
			}
		}
	}
	return nil
}

func (cfg *spamFilter) auditLogAllowed(number string) {
	cfg.auditFileSIGHUPLock.RLock()
	defer cfg.auditFileSIGHUPLock.RUnlock()
	if cfg.auditAllowedNumbers != nil {
		err := writeCSV(cfg.auditAllowedNumbersCSV, []string{time.Now().Format(time.RFC3339), number})
		if err != nil {
			cfg.log.Error("Audit log: Error writing to audit allowed numbers: %v", err)
		}
	}
}

func (cfg *spamFilter) auditLogBlocked(number string, fileName string, lineNo int) {
	cfg.auditFileSIGHUPLock.RLock()
	defer cfg.auditFileSIGHUPLock.RUnlock()
	if cfg.auditBlockedNumbers != nil {
		err := writeCSV(cfg.auditBlockedNumbersCSV, []string{time.Now().Format(time.RFC3339), number, fileName, strconv.Itoa(lineNo)})
		if err != nil {
			cfg.log.Error("Audit log: Error writing to audit blocked numbers: %v", err)
		}
	}
}

func (cfg *spamFilter) closeAuditFiles(lock bool) {
	if lock {
		cfg.auditFileSIGHUPLock.Lock()
		defer cfg.auditFileSIGHUPLock.Unlock()
	}
	if cfg.auditBlockedNumbers != nil {
		cfg.auditBlockedNumbersCSV.Flush()
		if err := cfg.auditBlockedNumbersCSV.Error(); err != nil {
			cfg.log.Error("Audit log: Error flushing audit blocked numbers: %v", err)
		}
		cfg.auditBlockedNumbers.Close()
		cfg.auditBlockedNumbersCSV = nil
		cfg.auditBlockedNumbers = nil
	}
	if cfg.auditAllowedNumbers != nil {
		cfg.auditAllowedNumbersCSV.Flush()
		if err := cfg.auditAllowedNumbersCSV.Error(); err != nil {
			cfg.log.Error("Audit log: Error flushing audit allowed numbers: %v", err)
		}
		cfg.auditAllowedNumbers.Close()
		cfg.auditAllowedNumbersCSV = nil
		cfg.auditAllowedNumbers = nil
	}
}

func writeCSV(csv *csv.Writer, data []string) error {
	if err := csv.Write(data); err != nil {
		return fmt.Errorf("write-csv: %v", err)
	}
	csv.Flush()
	if err := csv.Error(); err != nil {
		return fmt.Errorf("flush-csv: %v", err)
	}
	return nil
}
