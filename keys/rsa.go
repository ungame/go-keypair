package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

const (
	DefaultRSABitSize        = 4096
	DefaultRSAPrivateKeyType = "PRIVATE KEY"
	DefaultRSAPublicKeyType  = "PUBLIC KEY"
	DefaultRSAPrivateKeyFile = "id_rsa"
	DefaultRSAPublicKeyFile  = DefaultRSAPrivateKeyFile + ".pub"
)

type rsaKeyPair struct {
	privateKey *rsa.PrivateKey
}

func newRSA() KeyPair {
	kp := new(rsaKeyPair)

	var err error

	kp.privateKey, err = rsa.GenerateKey(rand.Reader, DefaultRSABitSize)
	if err != nil {
		log.Fatalln("error on create rsa keypair: ", err.Error())
	}

	return kp
}

func (kp *rsaKeyPair) GetPrivate() []byte {

	privateKey := x509.MarshalPKCS1PrivateKey(kp.privateKey)

	block := pem.Block{
		Type:  DefaultRSAPrivateKeyType,
		Bytes: privateKey,
	}

	return pem.EncodeToMemory(&block)
}

func (kp *rsaKeyPair) GetPublic() []byte {
	publicKey, err := x509.MarshalPKIXPublicKey(&kp.privateKey.PublicKey)
	if err != nil {
		log.Fatalln("error on encode public key: ", err.Error())
	}

	block := pem.Block{
		Type:  DefaultRSAPublicKeyType,
		Bytes: publicKey,
	}

	return pem.EncodeToMemory(&block)
}
func (kp *rsaKeyPair) String() string {
	return fmt.Sprintf(`
KEY PAIR:

%s

%s
`,
		kp.GetPrivate(),
		kp.GetPublic())
}
func (kp *rsaKeyPair) Write(dir string) error {
	filename := filepath.Join(dir, DefaultRSAPrivateKeyFile)
	perm := os.FileMode(0600)

	err := ioutil.WriteFile(filename, kp.GetPrivate(), perm)
	if err != nil {
		return err
	}

	filename = filepath.Join(dir, DefaultRSAPublicKeyFile)

	return ioutil.WriteFile(filename, kp.GetPublic(), perm)
}
