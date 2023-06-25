package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func check(e error) {
	if e != nil {
		fmt.Printf("%v\n", e.Error())
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:     "mailio",
	Short:   "Mailio is a secure, decentralized, and privacy-preserving email service",
	Long:    `Mailio is a secure, decentralized, and privacy-preserving email service. It is built on top of the Mailio protocol for secure, private, and censorship-resistant communication.`,
	Version: "0.1.0",
	Run: func(cmd *cobra.Command, args []string) {
		// empty
	},
}

func main() {
	Execute()
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		panic(err)
	}
}
