package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the vx.yaml configuration file structure.
type Config struct {
	Target  string   `yaml:"target"`
	Threads int      `yaml:"threads"`
	Timeout int      `yaml:"timeout"`
	Modules []string `yaml:"modules"`
	CI      CIConfig `yaml:"ci"`
	Output  OutputConfig `yaml:"output"`
	Ignore  []string `yaml:"ignore"`
}

// CIConfig holds CI/CD related options.
type CIConfig struct {
	MinScore    int  `yaml:"min-score"`
	FailOnScore bool `yaml:"fail-on-score"`
}

// OutputConfig holds output file paths.
type OutputConfig struct {
	SARIF    string `yaml:"sarif"`
	Badge    string `yaml:"badge"`
	JSON     string `yaml:"json"`
	HTML     string `yaml:"html"`
	Markdown string `yaml:"markdown"`
}

// LoadConfig reads a vx.yaml file from the given path.
// Returns nil, nil if the file does not exist.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return &cfg, nil
}
