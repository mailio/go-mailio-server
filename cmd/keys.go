package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	mCrypto "github.com/mailio/go-mailio-core/crypto"
	"github.com/spf13/cobra"
)

var outputFile string

func init() {
	keysCmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file (default is stdout)")
	rootCmd.AddCommand(keysCmd)
}

// keyCmd represents the keys command which generates ed25519 keys for use with Mailio Server and your DNS record of your domain
var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Generate ed25519 keys",
	Long:  "Generate ed25519 keys for use with Mailio Server",
	Run: func(cmd *cobra.Command, args []string) {
		// Generate ed25519 keys
		mc := mCrypto.NewMailioCrypto()
		_, private, err := mc.GenerateKeyPair()
		if err != nil {
			panic(err)
		}
		keysJson := map[string]interface{}{
			"type":       "mailio_server_keys_ed25519",
			"privateKey": *private,
			"created":    time.Now().UnixMilli(),
		}
		fileBytes, err := json.MarshalIndent(keysJson, "", "  ")
		if outputFile != "" {
			// save keys to disk in a file
			// fail if file already exists
			if _, err := os.Stat(outputFile); !errors.Is(err, os.ErrNotExist) {
				fmt.Printf("File already exists: %s\n", outputFile)
				os.Exit(1)
			}
			check(err)
			err = ioutil.WriteFile(outputFile, fileBytes, 0644)
			check(err)
			fmt.Printf("Output file: %s\n", outputFile)
		} else {
			fmt.Printf("\n%s\n", string(fileBytes))
		}
	},
}
