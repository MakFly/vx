package engine

import "time"

type Config struct {
	TargetURL string
	Threads   int
	Timeout   time.Duration
	UserAgent string
	Modules   []string // empty = all registered modules
	Silent    bool
}
