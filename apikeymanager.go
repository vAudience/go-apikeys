package apikeys

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/itsatony/go-datarepository"
)

type APIKeyManager struct {
	config    *Config
	logger    LogAdapter
	repo      datarepository.DataRepository
	limiter   *RateLimiter
	Version   string
	framework HTTPFramework
}

func New(config *Config) (*APIKeyManager, error) {
	logger := emptyLogger
	if config.Logger != nil {
		logger = config.Logger
	}

	if config.Repository == nil {
		return nil, fmt.Errorf("repository is required")
	}

	var limiter *RateLimiter
	if config.EnableRateLimit {
		limiter = NewRateLimiter(config.Repository, config.RateLimitRules)
	}

	if config.ApiKeyLength < 6 || config.ApiKeyLength > 64 {
		config.ApiKeyLength = APIKEY_RANDOMSTRING_LENGTH
	}
	if config.ApiKeyPrefix == "" {
		config.ApiKeyPrefix = APIKEY_PREFIX
	}
	APIKEY_PREFIX = config.ApiKeyPrefix
	APIKEY_RANDOMSTRING_LENGTH = config.ApiKeyLength

	if config.Framework == nil {
		return nil, fmt.Errorf("HTTP framework is required")
	}

	manager := &APIKeyManager{
		config:    config,
		logger:    logger,
		repo:      config.Repository,
		limiter:   limiter,
		Version:   Version,
		framework: config.Framework,
	}

	logger("INFO", fmt.Sprintf("[GO-APIKEYS.New] API key manager created (%s)", manager.Version))
	return manager, nil
}

func (m *APIKeyManager) UserID(c interface{}) string {
	apiKeyInfo := m.Get(c)
	if apiKeyInfo == nil {
		return ""
	}
	return apiKeyInfo.UserID
}

func (m *APIKeyManager) APIKey(c interface{}) string {
	apiKeyInfo := m.Get(c)
	if apiKeyInfo == nil {
		return ""
	}
	return apiKeyInfo.APIKeyHash
}

func (m *APIKeyManager) OrgID(c interface{}) string {
	apiKeyInfo := m.Get(c)
	if apiKeyInfo == nil {
		return ""
	}
	return apiKeyInfo.OrgID
}

func (m *APIKeyManager) Name(c interface{}) string {
	apiKeyInfo := m.Get(c)
	if apiKeyInfo == nil {
		return ""
	}
	return apiKeyInfo.Name
}

func (m *APIKeyManager) Email(c interface{}) string {
	apiKeyInfo := m.Get(c)
	if apiKeyInfo == nil {
		return ""
	}
	return apiKeyInfo.Email
}

func (m *APIKeyManager) Metadata(c interface{}) map[string]any {
	apiKeyInfo := m.Get(c)
	if apiKeyInfo == nil {
		return nil
	}
	return apiKeyInfo.Metadata
}

func (m *APIKeyManager) Get(c interface{}) *APIKeyInfo {
	value := m.framework.GetContextValue(c, LOCALS_KEY_APIKEYS)
	if value == nil {
		return nil
	}
	apiKeyInfo, ok := value.(*APIKeyInfo)
	if !ok {
		m.logger("ERROR", fmt.Sprintf("API key information not found in context: %v", value))
		return nil
	}
	return apiKeyInfo
}

func (m *APIKeyManager) CreateAPIKey(ctx context.Context, apiKeyInfo *APIKeyInfo) (*APIKeyInfo, error) {
	var apiKey string
	var hash string
	var hint string
	var err error
	if apiKeyInfo == nil {
		return nil, fmt.Errorf("API key info is required")
	}
	if apiKeyInfo.APIKey != "" { // if the API key is provided, use it
		apiKey = apiKeyInfo.APIKey
	}
	hash, hint, err = GenerateAPIKeyHash(apiKey)
	if err != nil {
		return nil, fmt.Errorf("error generating API key hash: %w", err)
	}
	apiKeyInfo.APIKeyHash = hash
	apiKeyInfo.APIKeyHint = hint
	apiKeyInfo.APIKey = "" // we are NOT saving the real key in the DB!

	err = m.repo.Upsert(ctx, datarepository.SimpleIdentifier(apiKeyInfo.APIKeyHash), apiKeyInfo)
	if err != nil {
		return nil, fmt.Errorf("error creating API key: %w", err)
	}

	// Set the clear API key for the caller (once)
	apiKeyInfo.APIKey = apiKey
	return apiKeyInfo, nil
}

func (m *APIKeyManager) GetAPIKeyInfo(ctx context.Context, apiKeyOrHash string) (*APIKeyInfo, error) {
	var apiKeyInfo APIKeyInfo
	var identifier datarepository.EntityIdentifier

	if IsApiKey(apiKeyOrHash) {
		hash, _, err := GenerateAPIKeyHash(apiKeyOrHash)
		if err != nil {
			return nil, fmt.Errorf("error generating API key hash: %w", err)
		}
		identifier = datarepository.SimpleIdentifier(hash)
	} else {
		identifier = datarepository.SimpleIdentifier(apiKeyOrHash)
	}

	err := m.repo.Read(ctx, identifier, &apiKeyInfo)
	if err != nil {
		if datarepository.IsNotFoundError(err) {
			return nil, ErrAPIKeyNotFound
		}
		return nil, fmt.Errorf("error retrieving API key info: %w", err)
	}

	return &apiKeyInfo, nil
}

func (m *APIKeyManager) SetAPIKeyInfo(ctx context.Context, apiKeyInfo *APIKeyInfo) error {
	err := m.repo.Update(ctx, datarepository.SimpleIdentifier(apiKeyInfo.APIKeyHash), apiKeyInfo)
	if err != nil {
		return fmt.Errorf("error updating API key: %w", err)
	}
	return nil
}

func (m *APIKeyManager) UpdateAPIKey(ctx context.Context, apiKeyInfo *APIKeyInfo) error {
	err := m.repo.Update(ctx, datarepository.SimpleIdentifier(apiKeyInfo.APIKeyHash), apiKeyInfo)
	if err != nil {
		return fmt.Errorf("error updating API key: %w", err)
	}
	return nil
}

func (m *APIKeyManager) DeleteAPIKey(ctx context.Context, apiKeyOrHash string) error {
	var identifier datarepository.EntityIdentifier

	if IsApiKey(apiKeyOrHash) {
		hash, _, err := GenerateAPIKeyHash(apiKeyOrHash)
		if err != nil {
			return fmt.Errorf("error generating API key hash: %w", err)
		}
		identifier = datarepository.SimpleIdentifier(hash)
	} else {
		identifier = datarepository.SimpleIdentifier(apiKeyOrHash)
	}

	err := m.repo.Delete(ctx, identifier)
	if err != nil {
		if datarepository.IsNotFoundError(err) {
			return ErrAPIKeyNotFound
		}
		return fmt.Errorf("error deleting API key: %w", err)
	}
	return nil
}

func (m *APIKeyManager) SearchAPIKeys(ctx context.Context, offset, limit int) ([]*APIKeyInfo, error) {
	// results, err := m.repo.Search(ctx, query, offset, limit, "created_at", "DESC")
	// pattern := datarepository.RedisIdentifier{EntityPrefix: "", ID: "*"}
	pattern := "*"
	// m.logger("DEBUG", fmt.Sprintf("Search pattern: (%v)", pattern))
	_, entities, err := m.repo.List(ctx, pattern)
	if err != nil {
		return nil, fmt.Errorf("error searching API keys: %w", err)
	}

	apiKeyInfos := make([]*APIKeyInfo, 0, len(entities))
	for _, entity := range entities {
		m.logger("DEBUG", fmt.Sprintf("Entity: %v", entity))
		var apiKeyInfo APIKeyInfo
		entityString, ok := entity.(string)
		if !ok {
			continue
		}
		err := json.Unmarshal([]byte(entityString), &apiKeyInfo)
		if err != nil {
			continue
		}
		apiKeyInfos = append(apiKeyInfos, &apiKeyInfo)
	}
	// m.logger("DEBUG", fmt.Sprintf("(%d)Search results: %v", len(entities), apiKeyInfos))
	return apiKeyInfos, nil
}
