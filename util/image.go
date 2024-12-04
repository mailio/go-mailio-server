package util

import (
	"bytes"
	"errors"
	"image"
	"image/jpeg"
	"image/png"
)

/*
	ParseImageBytes parses the image bytes and returns the image.Image object

Supported mime types are "image/jpg", "image/jpeg", "image/png"
  - @param content []byte
  - @param mimeType string
  - @return image.Image
  - @return error
*/
func ParseImageBytesToJPG(content []byte, mimeType string) (image.Image, error) {
	if len(content) == 0 {
		return nil, errors.New("empty content")
	}
	var decodeErr error
	var img image.Image
	switch mimeType {
	case "image/jpg", "image/jpeg":
		img, decodeErr = jpeg.Decode(bytes.NewReader(content))
	case "image/png":
		img, decodeErr = png.Decode(bytes.NewReader(content))
		if decodeErr == nil {
			// convert to jpeg
			buf := new(bytes.Buffer)
			jpeg.Encode(buf, img, &jpeg.Options{Quality: 83})
			img, decodeErr = jpeg.Decode(buf)
		}
	default:
		return nil, errors.New("unsupported image type")
	}
	return img, decodeErr
}
