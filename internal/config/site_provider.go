package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/humanjuan/golyn/config/loaders"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal/utils"
)

// SiteProvider manages per-site configuration in memory and reloads it when the
// configuration hash changes. Hash is computed only from the .conf file.
type SiteProvider struct {
	mu sync.RWMutex

	sites map[string]*siteEntry
}

type siteEntry struct {
	SiteName   string
	ConfigPath string
	Hash       string
	LoadedAt   time.Time
	Config     loaders.SiteConfig
}

func NewSiteProvider() *SiteProvider {
	return &SiteProvider{sites: make(map[string]*siteEntry)}
}

// GetSiteConfig returns the latest SiteConfig for a given site.
// If the config file hash changes, it reloads and updates the in-memory cache.
func (p *SiteProvider) GetSiteConfig(siteName, configPath string) (loaders.SiteConfig, error) {
	if siteName == "" {
		return loaders.SiteConfig{}, fmt.Errorf("siteName is empty")
	}
	if configPath == "" {
		return loaders.SiteConfig{}, fmt.Errorf("configPath is empty")
	}

	newHash, err := hashFile(configPath)
	if err != nil {
		return loaders.SiteConfig{}, err
	}

	// fast path
	p.mu.RLock()
	entry, ok := p.sites[siteName]
	if ok && entry.Hash == newHash {
		cfg := entry.Config
		p.mu.RUnlock()
		return cfg, nil
	}
	p.mu.RUnlock()

	// slow path: reload
	p.mu.Lock()
	defer p.mu.Unlock()

	// re-check after lock
	entry, ok = p.sites[siteName]
	if ok && entry.Hash == newHash {
		return entry.Config, nil
	}

	basePath, err := utils.GetBasePath()
	if err != nil {
		return loaders.SiteConfig{}, err
	}

	server := globals.GetConfig().Server
	siteCfg, err := loaders.LoadSiteConfig(siteName, configPath, basePath, server)
	if err != nil {
		return loaders.SiteConfig{}, err
	}

	p.sites[siteName] = &siteEntry{
		SiteName:   siteName,
		ConfigPath: configPath,
		Hash:       newHash,
		LoadedAt:   time.Now(),
		Config:     siteCfg,
	}

	return siteCfg, nil
}

func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}
