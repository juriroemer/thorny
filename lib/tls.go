package lib

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"go.yaml.in/yaml/v4"
)

type TlsUserConfig struct {
	CertPath      string   `yaml:"certPath"`
	KeyPath       string   `yaml:"keyPath"`
	Organization  string   `yaml:"organization"`
	Country       string   `yaml:"country"`
	Province      string   `yaml:"province"`
	Locality      string   `yaml:"locality"`
	StreetAddress string   `yaml:"streetAddress"`
	PostalCode    string   `yaml:"postalCode"`
	CommonName    string   `yaml:"commonName"`
	DnsNames      []string `yaml:"dnsNames"`
	DaysValid     int      `yaml:"daysValid"`
	Ips           []net.IP
}

func NewTlsUserConfig(raw any, ips []net.IP) (*TlsUserConfig, error) {
	conf := &TlsUserConfig{
		CertPath:      "./cert/tls.cert",
		KeyPath:       "/cert/tls.pem",
		Organization:  "Internet Company",
		Country:       "DE",
		Province:      "NRW",
		Locality:      "Muenster",
		StreetAddress: "Einsteinstrasse",
		PostalCode:    "48149",
		CommonName:    "IC",
		Ips:           ips,
		//DnsNames:
		DaysValid: 31,
	}
	valuesYaml, _ := yaml.Marshal(raw)

	if err := yaml.Unmarshal(valuesYaml, conf); err != nil {
		return nil, err
	}

	fmt.Println(conf)
	return conf, nil
}

func GenerateSelfSignedCert(conf *TlsUserConfig) error {
	// TODO only generate if they do not exist
	key, err := generatePrivateKey()
	if err != nil {
		return err
	}

	tmpl, err := certificateTemplate(conf)
	if err != nil {
		return err
	}

	certDer, err := selfSignCert(tmpl, key)
	if err != nil {
		return err
	}

	return writePEMFiles(certDer, key, conf.CertPath, conf.KeyPath)
}

func generatePrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2046)
}

func certificateTemplate(conf *TlsUserConfig) (*x509.Certificate, error) {

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,

		Subject: pkix.Name{
			Organization:  []string{conf.Organization},
			Country:       []string{conf.Country},
			Province:      []string{conf.Province},
			Locality:      []string{conf.Locality},
			StreetAddress: []string{conf.StreetAddress},
			PostalCode:    []string{conf.PostalCode},
			CommonName:    conf.CommonName,
		},

		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Duration(conf.DaysValid) * 24 * time.Hour),

		KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},

		BasicConstraintsValid: true,

		IPAddresses: conf.Ips,
		DNSNames:    conf.DnsNames,
	}

	return tmpl, nil
}

func selfSignCert(
	tmpl *x509.Certificate,
	key *rsa.PrivateKey,
) ([]byte, error) {

	certDER, err := x509.CreateCertificate(
		rand.Reader,
		tmpl,
		tmpl, // self-signed: parent == template
		&key.PublicKey,
		key,
	)
	if err != nil {
		return nil, err
	}

	return certDER, nil
}

func writePEMFiles(
	certDER []byte,
	key *rsa.PrivateKey,
	certPath, keyPath string,
) error {

	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certOut.Close()

	pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}

	keyOut, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer keyOut.Close()

	pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	})

	return nil
}
