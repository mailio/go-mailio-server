package util

import "time"

func GetTimestamp() int64 {
	return time.Now().UTC().UnixMilli()
}
