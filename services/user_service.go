package services

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

type UserService struct {
	repo repository.Repository
}

func NewUserService(repo repository.Repository) *UserService {
	return &UserService{
		repo: repo,
	}
}

// CreateUser creates a new user with the given email and password.
// It returns a pointer to an InputEmailPassword struct and an error (if any).
func (us *UserService) CreateUser(user *types.User, password string) (*types.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := us.repo.Save(ctx, fmt.Sprintf("/_users/org.couchdb.user:%s", user.Email), map[string]interface{}{"email": user.Email, "password": password, "roles": []string{}, "type": "user"})
	if err != nil {
		global.Logger.Log(err, "Failed to register user")
		return nil, err
	}

	hexEmail := "userdb-" + util.HexEncodeToString(user.Email)

	// wait for database to be created
	for i := 1; i < 5; i++ {
		resp, _ := us.repo.GetByID(ctx, hexEmail)
		doc := resp.(resty.Response)
		hErr := handleError(doc.Body())
		if hErr != nil {
			if hErr.Error() == "not_found" {
				backoff := int(100 * math.Pow(2, float64(i)))
				time.Sleep(time.Duration(backoff) * time.Millisecond)
				continue
			} else {
				return nil, hErr
			}
		}
	}

	// create index on database
	folderIndex := map[string]interface{}{
		"index": map[string]interface{}{
			"fields": []map[string]interface{}{{"folder": "desc"}, {"created": "desc"}},
		},
		"name": "folder-index",
		"type": "json",
		"ddoc": "folder-index",
	}
	err = us.repo.Save(ctx, fmt.Sprintf("/%s/_index", hexEmail), folderIndex)
	if err != nil {
		return nil, err
	}

	return user, nil
}
