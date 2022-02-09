package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/regnull/easyecc"
	"github.com/regnull/eccrsa"
)

func main() {
	var keyPath string
	flag.StringVar(&keyPath, "key", "", "ECC key path")
	flag.Parse()

	if keyPath == "" {
		log.Fatal("--key must be specified")
	}

	key, err := easyecc.NewPrivateKeyFromFile(keyPath, "")
	if err != nil {
		log.Fatal(err)
	}
	rsaKey, err := eccrsa.DeriveKey(key.ToECDSA(), 4096)
	if err != nil {
		log.Fatal(err)
	}

	jwkKey, err := jwk.New(rsaKey)
	if err != nil {
		log.Fatal(err)
	}

	buf, err := json.MarshalIndent(jwkKey, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", buf)
}
