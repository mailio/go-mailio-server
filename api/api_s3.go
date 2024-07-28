package api

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gin-gonic/gin"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
)

const lifetimeSecs = 60 * 60 * 30 // duration for which presigned url is valid (30 minutes)

type S3Api struct {
	env       *types.Environment
	s3Service *services.S3Service
}

func NewS3Api(s3Service *services.S3Service, env *types.Environment) *S3Api {
	return &S3Api{
		env:       env,
		s3Service: s3Service,
	}
}

// GetPresignedUrlPut
// @Summary GetObject makes a presigned request that can be used to get an object from a bucket.
// @Description The presigned request is valid for the specified number of seconds.
// @Tags S3
// @Param objectKey query string true "objectKey"
// @Param method query string true "method"
// @Success 200 {object} types.PresignedUrl
// @Failure 400 {object} api.ApiError "invalid api call"
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Failure 500 {object} api.ApiError "error creating presigned url"
// @Accept json
// @Produce json
// @Router /api/v1/s3presign [get]
func (pa *S3Api) GetPresignedUrlPut(c *gin.Context) {
	address, exists := c.Get("subjectAddress")
	if !exists {
		ApiErrorf(c, http.StatusBadRequest, "not authorized")
		return
	}
	objectKey := strings.ToLower(c.Query("objectKey"))
	method := strings.ToLower(c.Query("method"))
	if method != "get" && method != "put" {
		ApiErrorf(c, http.StatusBadRequest, "method must be PUT or POST")
		return
	}
	if objectKey == "" {
		ApiErrorf(c, http.StatusBadRequest, "objectKey is required")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var request v4.PresignedHTTPRequest
	var err error

	m5 := md5.New()
	m5.Write([]byte(objectKey))
	m5Sum := m5.Sum(nil)
	path := address.(string) + "/" + hex.EncodeToString(m5Sum)

	if method == "put" {
		r, e := pa.env.S3PresignClient.PresignPutObject(ctx, &s3.PutObjectInput{
			Bucket: &global.Conf.Storage.Bucket,
			Key:    &path,
		}, func(opts *s3.PresignOptions) {
			opts.Expires = time.Duration(lifetimeSecs * int64(time.Second))
		})
		request = *r
		err = e
	} else {
		r, e := pa.env.S3PresignClient.PresignGetObject(ctx, &s3.GetObjectInput{
			Bucket: &global.Conf.Storage.Bucket,
			Key:    &objectKey,
		}, func(opts *s3.PresignOptions) {
			opts.Expires = time.Duration(lifetimeSecs * int64(time.Second))
		})
		request = *r
		err = e
	}
	if err != nil {
		global.Logger.Log("error", "error creating presigned url", "error", err)
		ApiErrorf(c, http.StatusInternalServerError, "error creating presigned url: %v", err)
		return
	}
	c.JSON(http.StatusOK, types.PresignedUrl{Url: request.URL})
}

// Delete s3 object
// @Summary Delete object from s3 bucket
// @Description Delete object from s3 bucket (only in logged in users folder)
// @Tags S3
// @Param objectKey query string true "objectKey"
// @Success 200 {object} types.PresignedUrl
// @Failure 400 {object} api.ApiError "invalid api call"
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Failure 500 {object} api.ApiError "error deletin object"
// @Accept json
// @Produce json
// @Router /api/v1/s3 [delete]
func (pa *S3Api) DeleteObject(c *gin.Context) {
	address, exists := c.Get("subjectAddress")
	if !exists {
		ApiErrorf(c, http.StatusBadRequest, "not authorized")
		return
	}
	objectKey := strings.ToLower(c.Query("objectKey"))
	if objectKey == "" {
		ApiErrorf(c, http.StatusBadRequest, "objectKey is required")
		return
	}
	path := address.(string) + "/" + objectKey

	dErr := pa.s3Service.DeleteAttachment(global.Conf.Storage.Bucket, path)
	if dErr != nil {
		if dErr == types.ErrNotFound {
			ApiErrorf(c, http.StatusNotFound, "file not found")
			return
		}
		if dErr == types.ErrNotAuthorized {
			ApiErrorf(c, http.StatusForbidden, "forbidden to delete")
			return
		}
		global.Logger.Log("error", "failed to delete object")
		ApiErrorf(c, http.StatusInternalServerError, "failed to delete object")
		return
	}

	c.JSON(http.StatusOK, types.PresignedUrl{Url: path})
}
