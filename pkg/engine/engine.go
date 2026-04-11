package engine

import (
	"fmt"
	"sync"
	"time"
)

type Module interface {
	Name() string
	Description() string
	Run(cfg *Config) ([]Finding, error)
}

type Engine struct {
	Config  *Config
	modules []Module
}

func New(cfg *Config) *Engine {
	return &Engine{Config: cfg}
}

func (e *Engine) Register(m Module) {
	e.modules = append(e.modules, m)
}

func (e *Engine) Run() ScoreResult {
	start := time.Now()
	fmt.Printf("\n  ⚡ VX Security Scanner v0.1.0\n")
	fmt.Printf("  Target: %s\n", e.Config.TargetURL)
	fmt.Printf("  Modules: %d loaded\n\n", len(e.modules))

	var (
		allFindings []Finding
		mu          sync.Mutex
		wg          sync.WaitGroup
	)

	sem := make(chan struct{}, e.Config.Threads)

	for _, mod := range e.modules {
		if !e.shouldRun(mod) {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(m Module) {
			defer wg.Done()
			defer func() { <-sem }()

			fmt.Printf("  [~] Running %s...\n", m.Name())
			modStart := time.Now()

			findings, err := m.Run(e.Config)
			elapsed := time.Since(modStart)

			if err != nil {
				fmt.Printf("  [!] %s failed: %v (%s)\n", m.Name(), err, elapsed.Round(time.Millisecond))
				return
			}

			mu.Lock()
			allFindings = append(allFindings, findings...)
			mu.Unlock()

			fmt.Printf("  [✓] %s done — %d findings (%s)\n", m.Name(), len(findings), elapsed.Round(time.Millisecond))
		}(mod)
	}

	wg.Wait()

	elapsed := time.Since(start)
	fmt.Printf("\n  Scan completed in %s\n\n", elapsed.Round(time.Millisecond))

	return ComputeScore(allFindings)
}

func (e *Engine) shouldRun(m Module) bool {
	if len(e.Config.Modules) == 0 {
		return true
	}
	for _, name := range e.Config.Modules {
		if name == m.Name() {
			return true
		}
	}
	return false
}
