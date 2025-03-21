package repository

import (
	"context"
)

type Repository interface {
	GetByID(ctx context.Context, id string) (interface{}, error)
	GetAll(ctx context.Context, limit int, skip int) ([]interface{}, error)
	Save(ctx context.Context, docID string, data interface{}) error
	Update(ctx context.Context, id string, data interface{}) (interface{}, error)
	Delete(ctx context.Context, id string) error
	GetDBName() string
	GetClient() interface{}
}

type DBSelector interface {
	ChooseDB(dbName string) (Repository, error)
}
