package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"log"
	"math/big"
	"time"
)

type jsonConfig struct {
	Fingerprint string `json:"fingerprint"`
	Secret      string `json:"secret"`
}

func Configure(vars map[string]string) string {
	cert, priv, pub := genKeyPair()
	fingerprint := sha256.Sum256(pub)

	cfg := jsonConfig{
		Fingerprint: base64.StdEncoding.EncodeToString(fingerprint[:]),
		Secret:      genSecret(),
	}

	vars["REMOTESC_SECRET"] = cfg.Secret
	vars["REMOTESC_CERT"] = base64.StdEncoding.EncodeToString(cert)
	vars["REMOTESC_PRIV"] = base64.StdEncoding.EncodeToString(priv)

	j, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		log.Fatal(err)
	}
	return string(j)
}

func genKeyPair() ([]byte, []byte, []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "remotesc"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	rawCert, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		log.Fatal(err)
	}

	rawPriv, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		log.Fatal(err)
	}

	rawPublic, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		log.Fatal(err)
	}

	return rawCert, rawPriv, rawPublic
}

func genSecret() string {
	buf := make([]byte, 32)
	_, err := rand.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(buf)
}
