package repository

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/go-resty/resty/v2"
)

/**
* Object Mapper (from couchdb resty response to object based on the database name)
**/

func MapToObject(resp interface{}, obj interface{}) error {
	if response, ok := resp.(*resty.Response); ok {
		data := response.Body()

		// Check if obj is a pointer to a struct
		val := reflect.ValueOf(obj)
		if val.Kind() != reflect.Ptr || val.Elem().Kind() != reflect.Struct {
			return errors.New("obj is not a pointer to a struct")
		}

		err := json.Unmarshal(data, obj)
		if err != nil {
			return errors.New(fmt.Sprintf("%s cannot be mapped to the given object", response.Body()))
		}

		return nil
	}
	return errors.New("resp is not a resty.Response")
}
