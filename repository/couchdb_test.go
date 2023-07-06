package repository

import (
	"context"
	"fmt"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/mailio/go-mailio-server/types"
	"github.com/stretchr/testify/assert"
)

var url = "http://localhost:5689"

func InitMockDatabase(dbName string) (Repository, error) {
	httpmock.Activate()

	httpmock.RegisterResponder("GET", fmt.Sprintf("%s/%s", url, "_all_dbs"),
		httpmock.NewStringResponder(200, `[]`))

	mr, mErr := httpmock.NewJsonResponder(201, types.OK{IsOK: true})
	if mErr != nil {
		return nil, mErr
	}
	httpmock.RegisterResponder("PUT", fmt.Sprintf("%s/%s", url, dbName), mr)
	httpmock.RegisterResponder("HEAD", fmt.Sprintf("%s/%s", url, dbName), mr)
	httpmock.RegisterResponder("GET", fmt.Sprintf("%s/%s", url, dbName), mr)

	db, err := NewCouchDBRepository(url, "test", "test", "test", true)
	if err != nil {
		return nil, err
	}
	return db, nil
}

func deactivateMock() {
	httpmock.DeactivateAndReset()
}

func TestInitNewDatabase(t *testing.T) {
	db, err := InitMockDatabase("test")
	defer deactivateMock()
	if err != nil {
		t.Fatal(err)
	}
	if db == nil {
		t.Fatal("db is nil")
	}
}

func TestGetByID(t *testing.T) {
	db, _ := InitMockDatabase("test")
	defer deactivateMock()

	mk, _ := httpmock.NewJsonResponder(201, types.OK{IsOK: true})
	httpmock.RegisterResponder("POST", fmt.Sprintf("%s/%s", url, "test"), mk)

	mk, _ = httpmock.NewJsonResponder(200, types.BaseDocument{ID: "test"})
	httpmock.RegisterResponder("GET", fmt.Sprintf("%s/%s/%s", url, "test", "test"), mk)

	db.Save(context.Background(), "test", &types.BaseDocument{
		ID: "test",
	})
	res, err := db.GetByID(context.Background(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if res == nil {
		t.Fatal("res is nil")
	}
	assert.Equal(t, "test", res.(*types.BaseDocument).ID)
}
