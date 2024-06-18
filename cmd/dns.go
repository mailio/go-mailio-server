package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/mailio/go-mailio-server/util"
	"github.com/spf13/cobra"
)

var domain string
var publicKey string
var keyFile string

func init() {
	dnsCmd.Flags().StringVarP(&domain, "domain", "d", "", "domain name")
	dnsCmd.Flags().StringVarP(&publicKey, "publicKey", "p", "", "public key")
	dnsCmd.Flags().StringVarP(&keyFile, "keyFile", "f", "", "json file with stored public key")
	dnsCmd.MarkFlagRequired("domain")
	rootCmd.AddCommand(dnsCmd)
}

// dnsCmd represents the dns command which creates a TXT record for your Mailio Server
var dnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "Generate DNS records for Mailio Server",
	Long:  "Generate DNS records for your Mailio Server",
	PreRun: func(cmd *cobra.Command, args []string) {
		pubKey, _ := cmd.Flags().GetString("publicKey")
		if pubKey == "" {
			cmd.MarkFlagRequired("keyFile")
		}
	},
	Run: func(cmd *cobra.Command, args []string) {

		if publicKey == "" {
			content, err := os.ReadFile(keyFile)
			check(err)
			var keys map[string]interface{}
			err = json.Unmarshal(content, &keys)
			check(err)
			if keys["type"] != "mailio_server_keys_ed25519" {
				fmt.Printf("Invalid key file: %s\n", keyFile)
				os.Exit(1)
			}
			//TODO: overly complicated, refactor and just take 32 bytes from the private key
			if val, ok := keys["privateKey"]; ok {
				pk := val.(string)
				privateKeyBytes, pkErr := base64.StdEncoding.DecodeString(pk)
				check(pkErr)
				if len(privateKeyBytes) != 64 {
					fmt.Printf("Invalid lenght of private key (must be 64 but is %d): %s\n", len(privateKeyBytes), keyFile)
					os.Exit(1)
				}
				privateKey := ed25519.PrivateKey(privateKeyBytes)
				publicKey = base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))
			} else {
				fmt.Printf("Invalid key file: %s\n", keyFile)
				os.Exit(1)
			}
		}

		pk, err := base64.StdEncoding.DecodeString(publicKey)
		check(err)
		if len(pk) != 32 {
			fmt.Printf("Public key is not 32 bytes long: %s\n", publicKey)
			os.Exit(1)
		}

		txtRecord, err := util.GenerateTXTRecord(domain, publicKey)
		check(err)
		fmt.Printf("TXT record for %s:\n\n%s\n", domain, *txtRecord)
	},
}
