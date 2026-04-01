package cache

import "github.com/redis/go-redis/v9"

type Store struct {
	Client *redis.Client
}

func NewStore(client *redis.Client) Store {
	return Store{Client: client}
}
