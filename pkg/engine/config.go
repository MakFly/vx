package engine

import "time"

type Config struct {
	TargetURL   string
	Threads     int
	Timeout     time.Duration
	UserAgent   string
	Modules     []string // empty = all
	MinScore    int
	OutputJSON  bool
	Verbose     bool
}

func DefaultConfig(target string) *Config {
	return &Config{
		TargetURL: target,
		Threads:   10,
		Timeout:   15 * time.Second,
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
		MinScore:  70,
	}
}
