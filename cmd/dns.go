package main

import (
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
			var keys map[string]string
			err = json.Unmarshal(content, &keys)
			check(err)
			if keys["type"] != "mailio_server_keys_ed25519" {
				fmt.Printf("Invalid key file: %s\n", keyFile)
				os.Exit(1)
			}
			if val, ok := keys["publicKey"]; ok {
				publicKey = val
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
