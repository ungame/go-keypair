package main

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/ungame/go-keypair/examples/rsakeys/tokens"
	"github.com/ungame/go-keypair/keys"
	"log"
	"path/filepath"
	"runtime"
)

func main() {
	keypair := keys.New(keys.RSA)

	tokens.SetPrivateKey(keypair.GetPrivate())
	tokens.SetPublicKey(keypair.GetPublic())

	token, err := tokens.New(uuid.New().String())
	if err != nil {
		log.Panicln(err)
	}

	fmt.Println(tokens.ToString(token))

	_, f, _, _ := runtime.Caller(0)

	err = keypair.Write(filepath.Dir(f))
	if err != nil {
		log.Panicln(err)
	}
}
