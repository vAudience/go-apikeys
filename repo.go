// github.com/vaudience/go-apikeys/repo.go
package apikeys

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"

	"github.com/redis/go-redis/v9"
)

const (
	REDIS_KEY_PREFIX                        = "go-apikeys"
	REDIS_KEY_SEPARATOR                     = ":"
	REDIS_KEYCOMPONENT_JSONENTITY           = "json"
	REDIS_KEYCOMPONENT_SEARCH_INDEX         = "apikeys_index"
	REDIS_KEYCOMPONENT_SEARCH_INDEX_VERSION = "1"
)

var (
	ErrAPIKeyNotFound               = errors.New("API key not found")
	ErrUnexpectedSearchResultFormat = errors.New("unexpected search result format")
)

type Repository interface {
	GetAPIKeyInfo(apiKey string) (*APIKeyInfo, error)
	SearchAPIKeys(query string) ([]*APIKeyInfo, error)
	SetAPIKeyInfo(apiKeyInfo *APIKeyInfo) error
	DeleteAPIKeyInfo(apiKey string) error
	LoadKeysFromJSONFile(filePath string) error
	WriteAllAPIKeysToJSONFile(filePath string) error
}

type RedisRepository struct {
	client redis.UniversalClient
}

func NewRedisRepository(redisClient redis.UniversalClient) (*RedisRepository, error) {
	indexKey := assembleRedisKey(REDIS_KEYCOMPONENT_SEARCH_INDEX, REDIS_KEYCOMPONENT_SEARCH_INDEX_VERSION)

	// Check if our specific index version already exists
	_, err := redisClient.Do(context.Background(), "FT.INFO", indexKey).Result()
	if err != nil {
		if err == redis.Nil || err.Error() == "Unknown index name" {
			// Create the index if it doesn't exist
			_, err = redisClient.Do(context.Background(), "FT.CREATE", indexKey,
				"ON", "JSON",
				"PREFIX", "1", assembleRedisKey(REDIS_KEYCOMPONENT_JSONENTITY)+REDIS_KEY_SEPARATOR,
				"SCHEMA",
				"$.api_key", "AS", "api_key", "TAG",
				"$.user_id", "AS", "user_id", "TAG",
				"$.org_id", "AS", "org_id", "TAG",
				"$.name", "AS", "name", "TEXT",
				"$.email", "AS", "email", "TEXT",
				"$.roles[*]", "AS", "roles", "TAG",
				"$.rights[*]", "AS", "rights", "TAG",
			).Result()
			if err != nil {
				// log.Warnf("Failed to create search index[%s]: (%s)", indexKey, err.Error())
				return nil, err
			}
		} else {
			// log.Warnf("Failed to find search index[%s]: (%v)", indexKey, err.Error())
			return nil, err
		}
	}

	return &RedisRepository{
		client: redisClient,
	}, nil
}

func (r *RedisRepository) ListAllIndexVersions() ([]string, error) {
	pattern := assembleRedisKey(REDIS_KEYCOMPONENT_SEARCH_INDEX, "*")
	keys, err := r.client.Keys(context.Background(), pattern).Result()
	if err != nil {
		return nil, err
	}

	var versions []string
	for _, key := range keys {
		parts := strings.Split(key, REDIS_KEY_SEPARATOR)
		if len(parts) >= 3 {
			versions = append(versions, parts[2])
		}
	}

	return versions, nil
}

func (r *RedisRepository) DeleteOldIndexVersions(currentVersion string) error {
	versions, err := r.ListAllIndexVersions()
	if err != nil {
		return err
	}

	currentVersionInt, err := strconv.Atoi(currentVersion)
	if err != nil {
		return err
	}

	for _, version := range versions {
		versionInt, err := strconv.Atoi(version)
		if err != nil {
			continue
		}

		if versionInt < currentVersionInt {
			indexKey := assembleRedisKey(REDIS_KEYCOMPONENT_SEARCH_INDEX, version)
			_, err := r.client.Do(context.Background(), "FT.DROPINDEX", indexKey).Result()
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *RedisRepository) GetAPIKeyInfo(apiKey string) (*APIKeyInfo, error) {
	key := assembleRedisKey(REDIS_KEYCOMPONENT_JSONENTITY, apiKey)
	// Retrieve the API key information as a JSON data type
	data, err := r.client.Do(context.Background(), "JSON.GET", key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, ErrAPIKeyNotFound
		}
		return nil, err
	}
	jsonItems, ok := data.(string)
	if !ok {
		return nil, ErrInvalidJSON
	}
	var apiKeyInfo []APIKeyInfo
	err = json.Unmarshal([]byte(jsonItems), &apiKeyInfo)
	if err != nil {
		return nil, err
	}
	if len(apiKeyInfo) == 0 {
		return nil, ErrAPIKeyNotFound
	}
	return &apiKeyInfo[0], nil
}

func (r *RedisRepository) SearchAPIKeys(query string) ([]*APIKeyInfo, error) {
	// Perform the search query using FT.SEARCH
	res, err := r.client.Do(context.Background(), "FT.SEARCH", REDIS_KEYCOMPONENT_SEARCH_INDEX, query).Result()
	if err != nil {
		return nil, err
	}

	var apiKeyInfos []*APIKeyInfo

	// Check if the result is of the expected type
	searchResults, ok := res.([]any)
	if !ok || len(searchResults) < 2 {
		return apiKeyInfos, ErrUnexpectedSearchResultFormat
	}

	// Iterate over the search results
	anySlice, ok := searchResults[1].([]any)
	if !ok {
		return apiKeyInfos, ErrUnexpectedSearchResultFormat
	}
	for _, doc := range anySlice {
		// Check if the document is of the expected type
		docFields, ok := doc.([]any)
		if !ok || len(docFields) == 0 {
			continue
		}

		// Check if the last field is of type string
		jsonData, ok := docFields[len(docFields)-1].(string)
		if !ok {
			continue
		}

		var apiKeyInfo APIKeyInfo
		err := json.Unmarshal([]byte(jsonData), &apiKeyInfo)
		if err != nil {
			return nil, err
		}

		apiKeyInfos = append(apiKeyInfos, &apiKeyInfo)
	}

	return apiKeyInfos, nil
}

func (r *RedisRepository) DeleteAPIKeyInfo(apiKey string) error {
	key := assembleRedisKey(REDIS_KEYCOMPONENT_JSONENTITY, apiKey)
	_, err := r.client.Del(context.Background(), key).Result()
	if err != nil {
		return err
	}

	return nil
}

func (r *RedisRepository) SetAPIKeyInfo(apiKeyInfo *APIKeyInfo) error {
	key := assembleRedisKey(REDIS_KEYCOMPONENT_JSONENTITY, apiKeyInfo.APIKey)
	data, err := json.Marshal(apiKeyInfo)
	if err != nil {
		return err
	}

	// Save the API key information as a JSON data type
	err = r.client.Do(context.Background(), "JSON.SET", key, ".", string(data)).Err()
	if err != nil {
		return err
	}

	return nil
}

func assembleRedisKey(components ...string) string {
	return REDIS_KEY_PREFIX + REDIS_KEY_SEPARATOR + strings.Join(components, REDIS_KEY_SEPARATOR)
}

func (r *RedisRepository) LoadKeysFromJSONFile(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	var apiKeys map[string]*APIKeyInfo
	err = json.Unmarshal(data, &apiKeys)
	if err != nil {
		return err
	}

	for _, apiKeyInfo := range apiKeys {
		err = r.SetAPIKeyInfo(apiKeyInfo)
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *RedisRepository) WriteAllAPIKeysToJSONFile(filePath string) error {
	// Get all API key information from Redis
	apiKeys, err := r.getAllAPIKeys()
	if err != nil {
		return err
	}

	// Create a map to store the API keys
	apiKeysMap := make(map[string]*APIKeyInfo)

	// Iterate over the API keys and populate the map
	for _, apiKey := range apiKeys {
		apiKeyInfo, err := r.GetAPIKeyInfo(apiKey)
		if err != nil {
			return err
		}
		apiKeysMap[apiKey] = apiKeyInfo
	}

	// Marshal the API keys map to JSON
	data, err := json.MarshalIndent(apiKeysMap, "", "  ")
	if err != nil {
		return err
	}

	// Write the JSON data to the file
	err = os.WriteFile(filePath, data, 0644)
	if err != nil {
		return err
	}

	return nil
}

func (r *RedisRepository) getAllAPIKeys() ([]string, error) {
	pattern := assembleRedisKey(REDIS_KEYCOMPONENT_JSONENTITY, "*")
	keys, err := r.client.Keys(context.Background(), pattern).Result()
	if err != nil {
		return nil, err
	}

	var apiKeys []string
	for _, key := range keys {
		// Extract the API key from the Redis key
		apiKey := strings.TrimPrefix(key, REDIS_KEY_PREFIX+REDIS_KEY_SEPARATOR)
		apiKeys = append(apiKeys, apiKey)
	}

	return apiKeys, nil
}
