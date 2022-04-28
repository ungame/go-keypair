package keys

type Algorithm string

const (
	RSA   Algorithm = "RSA"
	ECDSA Algorithm = "ECDSA"
)

type KeyPair interface {
	GetPrivate() []byte
	GetPublic() []byte
	String() string
	Write(dir string) error
}

func New(alg Algorithm) KeyPair {
	switch alg {
	case RSA:
		return newRSA()

	case ECDSA:

	}
	return &unimplementedKeyPair{}
}

type unimplementedKeyPair struct {
}

func (kp *unimplementedKeyPair) GetPrivate() []byte {
	return []byte{}
}
func (kp *unimplementedKeyPair) GetPublic() []byte {
	return []byte{}
}
func (kp *unimplementedKeyPair) String() string {
	return ""
}
func (kp *unimplementedKeyPair) Write(_ string) error {
	return nil
}
