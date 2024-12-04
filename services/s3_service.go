package services

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	s3Service "github.com/aws/aws-sdk-go-v2/service/s3"
	s3Types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/types"
)

type S3Service struct {
	env *types.Environment
}

func NewS3Service(env *types.Environment) *S3Service {
	return &S3Service{
		env: env,
	}
}

// upload attachment to s3
func (s3s *S3Service) UploadAttachment(bucket, path string, content []byte, contentType string) (string, error) {
	if len(content) == 0 {
		return "", types.ErrBadRequest
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ioReader := bytes.NewReader(content)
	input := &s3Service.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(path),
		Body:   ioReader,
	}
	if contentType != "" {
		input.ContentType = aws.String(contentType)
	}

	_, uErr := s3s.env.S3Uploader.Upload(ctx, input)
	if uErr != nil {
		fmt.Printf("Error uploading to S3: %v\n", uErr)
		debug.PrintStack()
		global.Logger.Log(uErr.Error(), "failed to upload attachment", path)
		return "", uErr
	}
	return fmt.Sprintf("s3://%s/%s", bucket, path), nil
}

// Delete attachment at specific bucket and path
func (s3s *S3Service) DeleteAttachment(bucket, path string) error {
	input := &s3Service.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(path),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := s3s.env.S3Client.DeleteObject(ctx, input)
	if err != nil {
		var noKey *s3Types.NoSuchKey
		var apiErr *smithy.GenericAPIError
		if errors.As(err, &noKey) {
			global.Logger.Log("warning", "object does not exist", "objectKey", path)
			return types.ErrNotFound
		} else if errors.As(err, &apiErr) {
			switch apiErr.ErrorCode() {
			case "AccessDenied":
				global.Logger.Log("warning", "access denied", "objectKey", path)
				return types.ErrNotAuthorized
			}
			global.Logger.Log("error", "error deleting object", "error", err)
			return err
		}
	}
	global.Logger.Log("info", "object deleted", "objectKey", path)
	return nil
}

// download attachment from s3
func (s3 *S3Service) DownloadAttachment(attachmentUrl string) ([]byte, error) {
	if attachmentUrl == "" {
		return nil, types.ErrBadRequest
	}
	parsedURL, pErr := url.Parse(attachmentUrl)
	if pErr != nil {
		global.Logger.Log(pErr.Error(), "failed to parse attachment url")
		return nil, pErr
	}
	// Extract the file key from the path (after the first "/")
	fileKey := strings.TrimPrefix(parsedURL.Path, "/")
	if fileKey == "" {
		global.Logger.Log("error", "invalid attachment url", "attachmentUrl", attachmentUrl)
		return nil, types.ErrBadRequest
	}

	buf := manager.NewWriteAtBuffer([]byte{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := s3.env.S3Downloader.Download(ctx, buf, &s3Service.GetObjectInput{
		Bucket: aws.String(global.Conf.Storage.Bucket),
		Key:    aws.String(fileKey),
	})
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
