package sipspamfilter

import (
	"fmt"
	"time"
	"unicode"
)

type timeDuration time.Duration

func (t *timeDuration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	if len(s) == 0 {
		return nil
	}
	if !unicode.IsLetter(rune(s[len(s)-1])) {
		return fmt.Errorf("duration string must end with a time unit (ns, us, ms, s, m, h)")
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*t = timeDuration(d)
	return nil
}

func (t *timeDuration) ToDuration() time.Duration {
	return time.Duration(*t)
}

func (t timeDuration) MarshalYAML() (interface{}, error) {
	return time.Duration(t).String(), nil
}

type SpamFilterConfig struct {
	LogLevel    int                  `json:"log_level" yaml:"log_level" default:"4"`
	LocalAddr   string               `json:"local_addr" yaml:"local_addr" default:"0.0.0.0:0"`
	CountryCode string               `json:"country_code" yaml:"country_code" default:"44"`
	SIP         SpamFilterSip        `json:"sip" yaml:"sip"`
	AuditFiles  SpamFilterAuditFiles `json:"audit_files" yaml:"audit_files"`
	Spam        SpamFilterSpam       `json:"spam" yaml:"spam"`
}

type SpamFilterSip struct {
	User      string       `json:"user" yaml:"user"`
	Password  password     `json:"password" yaml:"password"`
	Host      string       `json:"host" yaml:"host"`
	Port      int          `json:"port" yaml:"port" default:"5060"`
	Expiry    timeDuration `json:"expiry" yaml:"expiry" default:"500s"`
	UserAgent string       `json:"user_agent" yaml:"user_agent"`
}

type SpamFilterSpam struct {
	TryToAnswerDelay timeDuration `json:"try_to_answer_delay" yaml:"try_to_answer_delay" default:"100ms"`
	AnswerDelay      timeDuration `json:"answer_delay" yaml:"answer_delay" default:"100ms"`
	HangupDelay      timeDuration `json:"hangup_delay" yaml:"hangup_delay" default:"1s"`
	BlacklistPaths   []string     `json:"blacklist_paths" yaml:"blacklist_paths"`
}

type SpamFilterAuditFiles struct {
	BlockedNumbers string `json:"blocked_numbers" yaml:"blocked_numbers"`
	AllowedNumbers string `json:"allowed_numbers" yaml:"allowed_numbers"`
}

type password string

func (p *password) UnmarshalYAML(unmarshal func(interface{}) error) error {
	return unmarshal((*string)(p))
}

func (p password) MarshalYAML() (interface{}, error) {
	return "********", nil
}
