package engine

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// defaultModuleTimeout is the per-module execution timeout.
const defaultModuleTimeout = 5 * time.Minute

// Module is the interface that all remote scan modules must implement.
type Module interface {
	Name() string
	Description() string
	Run(ctx context.Context, cfg *Config) ([]Finding, error)
}

// Engine holds the configuration and registered modules.
// Engine is not safe for concurrent use (Register must complete before Run).
type Engine struct {
	Config  *Config
	mu      sync.RWMutex
	modules []Module
}

func New(cfg *Config) *Engine {
	return &Engine{Config: cfg}
}

// Register adds a module to the engine.
// Register must not be called concurrently with Run or other Register calls.
func (e *Engine) Register(m Module) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.modules = append(e.modules, m)
}

// Run executes all registered modules concurrently and returns the scan result.
// Module errors are aggregated in ScoreResult.Errors; Run itself only returns an
// error for fatal configuration problems.
func (e *Engine) Run() (ScoreResult, error) {
	if e == nil || e.Config == nil {
		return ScoreResult{}, fmt.Errorf("engine: nil config")
	}

	threads := e.Config.Threads
	if threads < 1 {
		threads = 1
	}

	start := time.Now()
	if !e.Config.Silent {
		fmt.Printf("\n  ⚡ VX Security Scanner v0.1.0\n")
		fmt.Printf("  Target: %s\n", e.Config.TargetURL)
		fmt.Printf("  Modules: %d loaded\n\n", len(e.modules))
	}

	var (
		allFindings []Finding
		allErrors   []ModuleError
		mu          sync.Mutex
		wg          sync.WaitGroup
	)

	sem := make(chan struct{}, threads)

	e.mu.RLock()
	mods := make([]Module, len(e.modules))
	copy(mods, e.modules)
	e.mu.RUnlock()

	for _, mod := range mods {
		if !e.shouldRun(mod) {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(m Module) {
			defer wg.Done()
			defer func() { <-sem }()

			if !e.Config.Silent {
				fmt.Printf("  [~] Running %s...\n", m.Name())
			}
			modStart := time.Now()

			ctx, cancel := context.WithTimeout(context.Background(), defaultModuleTimeout)
			defer cancel()

			findings, err := m.Run(ctx, e.Config)
			elapsed := time.Since(modStart)

			if err != nil {
				if !e.Config.Silent {
					fmt.Printf("  [!] %s failed: %v (%s)\n", m.Name(), err, elapsed.Round(time.Millisecond))
				}
				mu.Lock()
				allErrors = append(allErrors, NewModuleError(m.Name(), err))
				mu.Unlock()
				return
			}

			mu.Lock()
			allFindings = append(allFindings, findings...)
			mu.Unlock()

			if !e.Config.Silent {
				fmt.Printf("  [✓] %s done — %d findings (%s)\n", m.Name(), len(findings), elapsed.Round(time.Millisecond))
			}
		}(mod)
	}

	wg.Wait()

	elapsed := time.Since(start)
	if !e.Config.Silent {
		fmt.Printf("\n  Scan completed in %s\n\n", elapsed.Round(time.Millisecond))
	}

	return ComputePartialScore(allFindings, allErrors), nil
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
