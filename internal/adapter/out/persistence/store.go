package persistence

import "gorm.io/gorm"

type Store struct {
	DB *gorm.DB
}

func NewStore(db *gorm.DB) Store {
	return Store{DB: db}
}
