// github.com/vaudience/go-apikeys/repo.go
package apikeys

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/redis/go-redis/v9"
)

const (
	REDIS_KEY_PREFIX                        = "go-apikeys"
	REDIS_KEY_SEPARATOR                     = ":"
	REDIS_KEYCOMPONENT_JSONENTITY           = "json"
	REDIS_KEYCOMPONENT_SEARCH_INDEX         = "searchindex_apikeys"
	REDIS_KEYCOMPONENT_SEARCH_INDEX_VERSION = "2"
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

func NewRedisRepository(redisClient redis.UniversalClient, logger func(logLevel string, logContent string)) (*RedisRepository, error) {
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
				// "$.api_key", "AS", "api_key", "TAG",
				"$.api_key_hash", "AS", "api_key_hash", "TAG",
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
			logger("INFO", fmt.Sprintf("[GO-APIKEYS.NewRedisRepository] Created search index: (%s)", indexKey))
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
	apiKeyHash, _, err := GenerateAPIKeyHash(apiKey)
	if err != nil {
		return nil, err
	}
	key := assembleRedisKey(REDIS_KEYCOMPONENT_JSONENTITY, apiKeyHash)
	// Retrieve the API key information as a JSON data type
	data, err := r.client.Do(context.Background(), "JSON.GET", key).Result()
	if err != nil {
		if err == redis.Nil {
			// fmt.Printf("API key not found: (%s) via key(%s)\n", apiKey, key)
			return nil, ErrAPIKeyNotFound
		}
		return nil, err
	}
	jsonItems, ok := data.(string)
	if !ok {
		return nil, ErrInvalidJSON
	}
	var apiKeyInfo APIKeyInfo
	err = json.Unmarshal([]byte(jsonItems), &apiKeyInfo)
	if err != nil {
		return nil, err
	}
	return &apiKeyInfo, nil
}

func (r *RedisRepository) SearchAPIKeys(query string, logger func(logLevel string, logContent string)) ([]*APIKeyInfo, error) {
	// Perform the search query using FT.SEARCH

	indexKey := assembleRedisKey(REDIS_KEYCOMPONENT_SEARCH_INDEX, REDIS_KEYCOMPONENT_SEARCH_INDEX_VERSION)
	resultJsonStrings, err := r.handleRedisSearch(indexKey, query, 0, 1000, "org_id", "DESC")
	if err != nil {
		logger("ERROR", fmt.Sprintf("[GO-APIKEYS.SearchAPIKeys] Failed to search for API keys: (%s)", err.Error()))
		return nil, err
	}

	// res, err := r.client.Do(context.Background(), "FT.SEARCH", indexKey, query).Result()

	var apiKeyInfos []*APIKeyInfo

	// logger("DEBUG", fmt.Sprintf("[GO-APIKEYS.SearchAPIKeys] Search results: (%v)", resultJsonStrings))

	// Iterate over the search results
	for _, doc := range resultJsonStrings {
		var apiKeyInfo APIKeyInfo
		err := json.Unmarshal([]byte(doc), &apiKeyInfo)
		if err != nil {
			return nil, err
		}

		apiKeyInfos = append(apiKeyInfos, &apiKeyInfo)
	}

	return apiKeyInfos, nil
}

func (r *RedisRepository) DeleteAPIKeyInfo(apiKey string) error {
	apiKeyHash, _, err := GenerateAPIKeyHash(apiKey)
	if err != nil {
		return err
	}
	key := assembleRedisKey(REDIS_KEYCOMPONENT_JSONENTITY, apiKeyHash)
	_, err = r.client.Del(context.Background(), key).Result()
	if err != nil {
		return err
	}

	return nil
}

func (r *RedisRepository) SetAPIKeyInfo(apiKeyInfo *APIKeyInfo) error {
	key := assembleRedisKey(REDIS_KEYCOMPONENT_JSONENTITY, apiKeyInfo.APIKeyHash)
	data, err := json.Marshal(apiKeyInfo)
	if err != nil {
		return err
	}
	// log.Printf("SetAPIKeyInfo:(%s)->(%s)", key, string(data))

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

func (r *RedisRepository) handleRedisSearch(index string, query string, offset int, max int, sortByField string, sortByDirection string) (resultJsonStrings []string, err error) {
	// logger.Debugf("[handleRedisSearch] Searching with query( FT.SEARCH (%s) (%s) NOCONTENT )", index, query)
	if offset < 0 {
		offset = 0
	}
	if max < 1 {
		max = 1
	}
	ctx := context.Background()
	answer, err := r.client.Do(ctx, "FT.SEARCH", index, query, "LIMIT", offset, max, "SORTBY", sortByField, sortByDirection).Result()
	// logger.Debugf("query: (%s)", strings.Join([]string{"FT.SEARCH", index, query, "LIMIT", strconv.Itoa(offset), strconv.Itoa(max), "SORTBY", sortByField, sortByDirection}, " "))
	// logger.Debugf("answer: (%v)", answer)
	if err != nil {
		// logger.Debugf("error: (%v)", err)
		if err == redis.Nil {
			// logger.Debugf("Nothing found with query( FT.SEARCH %s %s %s)", index, query, limit)
			return resultJsonStrings, nil
		}
		// logger.Debugf("Failed to search with query( FT.SEARCH %s %s %s): %v", index, query, limit, err)
		return resultJsonStrings, err
	}
	responseData, ok := answer.(map[any]any)
	if !ok {
		// logger.Errorf("unexpected result type 1: %T", answer)
		return resultJsonStrings, fmt.Errorf("unexpected result type: %T", answer)
	}
	raw_total_results, ok := responseData["total_results"]
	if !ok {
		// logger.Errorf("unexpected result type 2: %T", responseData)
		return resultJsonStrings, fmt.Errorf("unexpected result type: %T", responseData)
	}
	total_results, ok := raw_total_results.(int64)
	if !ok {
		// logger.Errorf("unexpected result type 3: %T", raw_total_results)
		return resultJsonStrings, fmt.Errorf("unexpected result type: %T", raw_total_results)
	}
	if total_results == 0 {
		// logger.Debugf("No resultJsonStrings found with query( FT.SEARCH %s %s)", index, query)
		return resultJsonStrings, nil
	}
	raw_errors, ok := responseData["error"]
	if ok {
		return resultJsonStrings, fmt.Errorf("search error: %v", raw_errors)
		// logger.Errorf("unexpected result type 4: %T", results)
		// return resultJsonStrings, fmt.Errorf("search error: %v", raw_errors)
	}
	answer_results, ok := responseData["results"]
	if !ok {
		// logger.Errorf("unexpected result type 5: %T", responseData)
		return resultJsonStrings, fmt.Errorf("unexpected result type: %T", responseData)
	}
	rawResults, ok := answer_results.([]any)
	if !ok {
		// logger.Errorf("unexpected result type 6: %T", answer_results)
		return resultJsonStrings, fmt.Errorf("unexpected result type: %T", answer_results)
	}
	for _, rawResult := range rawResults {
		result, ok := rawResult.(map[any]any)
		if !ok {
			// logger.Errorf("Result item format error: (%v)", rawResult)
			continue
		}
		extraAttributes, ok := result["extra_attributes"].(map[any]any)
		if !ok {
			// logger.Errorf("Extra attributes format error: %v", result["extra_attributes"])
			continue
		}

		jsonStr, ok := extraAttributes["$"].(string)
		if !ok {
			// logger.Errorf("Extra attributes '$' key error: %v", extraAttributes["$"])
			continue
		}
		resultJsonStrings = append(resultJsonStrings, jsonStr)
	}
	// logger.Debugf("Found %d results with query( FT.SEARCH %s %s %s)", len(resultJsonStrings), index, query, limit)
	return resultJsonStrings, nil
}
