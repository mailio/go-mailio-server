package services

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
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
func (s3s *S3Service) UploadAttachment(bucket, path string, content []byte) (string, error) {
	if len(content) == 0 {
		return "", types.ErrBadRequest
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ioReader := bytes.NewReader(content)
	_, uErr := s3s.env.S3Uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(path),
		Body:   ioReader,
	})
	if uErr != nil {
		global.Logger.Log(uErr.Error(), "failed to upload attachment", path)
		return "", uErr
	}
	return fmt.Sprintf("s3://%s%s", global.Conf.Storage.Bucket, path), nil
}

// Delete attachment at specific bucket and path
func (s3s *S3Service) DeleteAttachment(bucket, path string) error {
	input := &s3.DeleteObjectInput{
		Bucket: aws.String(global.Conf.Storage.Bucket),
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
	return nil
}

// download attachment from s3
// func (us *UserService) DownloadAttachment(attachmentUrl string) ([]byte, error) {
// 	if attachmentUrl == "" {
// 		return nil, types.ErrBadRequest
// 	}
// 	splitted := strings.Split(attachmentUrl, "s3://"+global.Conf.Storage.Bucket+"/")
// 	if len(splitted) != 2 {
// 		return nil, types.ErrBadRequest
// 	}
// 	buf := aws.NewWriteAtBuffer([]byte{})
// 	_, err := us.env.S3Downloader.Download(buf, &s3manager.DownloadInput{
// 		Bucket: aws.String(global.Conf.Storage.Bucket),
// 		Key:    aws.String(attachmentUrl),
// 	})
// 	if err != nil {
// 		return nil, err
// 	}
// 	return buf.Bytes(), nil
// }
