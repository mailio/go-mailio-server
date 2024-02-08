package util

import (
	"encoding/gob"
	"os"
	"sync"

	"github.com/mailio/go-mailio-server/types"
)

// I/O thread-safe file operations
type SafeFile struct {
	mu     sync.Mutex
	file   *os.File
	encode *gob.Encoder
	decode *gob.Decoder
}

type Data struct {
	Value []types.KeyValue
}

func NewSafeFile(filename string) (*SafeFile, error) {
	// Open the file
	file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}

	// Create the SafeFile object
	sf := &SafeFile{
		file:   file,
		encode: gob.NewEncoder(file),
		decode: gob.NewDecoder(file),
	}

	return sf, nil
}

func (sf *SafeFile) Close() error {
	// Close the file
	err := sf.file.Close()
	if err != nil {
		return err
	}

	return nil
}

func (sf *SafeFile) Read() (*Data, error) {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	info, err := sf.file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() == 0 {
		return nil, types.ErrNotFound
	}

	var data Data
	dErr := sf.decode.Decode(&data)
	return &data, dErr
}

func (sf *SafeFile) Write(data *Data) error {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	return sf.encode.Encode(data)
}
