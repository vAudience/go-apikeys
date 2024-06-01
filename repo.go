// github.com/vaudience/go-apikeys/repo.go
package apikeys

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/go-redis/redis/v8"
)

const (
	REDIS_KEY_PREFIX    = "go-apikeys"
	REDIS_KEY_SEPARATOR = ":"
)

var (
	ErrAPIKeyNotFound = errors.New("API key not found")
)

type Repository interface {
	GetAPIKeyInfo(apiKey string) (*APIKeyInfo, error)
	SaveAPIKeyInfo(apiKey string, apiKeyInfo *APIKeyInfo) error
	LoadAllKeysFromJSONFile(filePath string) error
	WriteAllAPIKeysToJSONFile(filePath string) error
	DeleteAPIKeyInfo(apiKey string) error
}

type RedisRepository struct {
	client redis.UniversalClient
}

func assembleRedisKey(components ...string) string {
	return REDIS_KEY_PREFIX + REDIS_KEY_SEPARATOR + strings.Join(components, REDIS_KEY_SEPARATOR)
}

func NewRedisRepository(client redis.UniversalClient) *RedisRepository {
	return &RedisRepository{
		client: client,
	}
}

func (r *RedisRepository) GetAPIKeyInfo(apiKey string) (*APIKeyInfo, error) {
	key := assembleRedisKey(apiKey)
	val, err := r.client.Get(context.Background(), key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, ErrAPIKeyNotFound
		}
		return nil, err
	}

	var apiKeyInfo APIKeyInfo
	err = json.Unmarshal([]byte(val), &apiKeyInfo)
	if err != nil {
		return nil, err
	}

	return &apiKeyInfo, nil
}

func (r *RedisRepository) SaveAPIKeyInfo(apiKey string, apiKeyInfo *APIKeyInfo) error {
	key := assembleRedisKey(apiKey)
	val, err := json.Marshal(apiKeyInfo)
	if err != nil {
		return err
	}

	err = r.client.Set(context.Background(), key, val, 0).Err()
	if err != nil {
		return err
	}

	return nil
}

func (r *RedisRepository) DeleteAPIKeyInfo(apiKey string) error {
	key := assembleRedisKey(apiKey)
	err := r.client.Del(context.Background(), key).Err()
	if err != nil {
		return err
	}
	return nil
}

func (r *RedisRepository) LoadAllKeysFromJSONFile(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	var apiKeys map[string]*APIKeyInfo
	err = json.Unmarshal(data, &apiKeys)
	if err != nil {
		return err
	}

	for apiKey, apiKeyInfo := range apiKeys {
		err = r.SaveAPIKeyInfo(apiKey, apiKeyInfo)
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *RedisRepository) WriteAllAPIKeysToJSONFile(filePath string) error {
	keys, err := r.client.Keys(context.Background(), assembleRedisKey("*")).Result()
	if err != nil {
		return err
	}

	apiKeys := make(map[string]*APIKeyInfo)
	for _, key := range keys {
		apiKey := strings.TrimPrefix(key, REDIS_KEY_PREFIX+REDIS_KEY_SEPARATOR)
		apiKeyInfo, err := r.GetAPIKeyInfo(apiKey)
		if err != nil {
			return err
		}
		apiKeys[apiKey] = apiKeyInfo
	}

	data, err := json.Marshal(apiKeys)
	if err != nil {
		return err
	}

	err = os.WriteFile(filePath, data, 0644)
	if err != nil {
		return err
	}

	return nil
}
