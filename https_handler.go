package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"
)

func getHostCert(r *http.Request) (tls.Certificate, error) {
	caCertFile := "ca.crt"
	caKeyFile := "ca.key"

	caKeyPem, err := os.ReadFile(caKeyFile)
	if err != nil {
		log.Printf("Failed to read ca.key", err)
		return tls.Certificate{}, err
	}
	caKeyBlock, _ := pem.Decode(caKeyPem)
	if caKeyBlock == nil {
		log.Printf("Failed to parse PEM block containing the key", err)
		return tls.Certificate{}, err
	}
	caPrivateKey, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		log.Printf("Failed to parse ca key", err)
		return tls.Certificate{}, err
	}

	caCertPem, err := os.ReadFile(caCertFile)
	if err != nil {
		log.Printf("Failed to read ca.crt", err)
		return tls.Certificate{}, err
	}
	caCertBlock, _ := pem.Decode(caCertPem)
	if caKeyBlock == nil {
		log.Printf("Failed to parse PEM block containing the crt", err)
		return tls.Certificate{}, err
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		log.Printf("Failed to parse priv key", err)
		return tls.Certificate{}, err
	}

	serverPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("Failed to generate priv key", err)
		return tls.Certificate{}, err
	}

	serverCertTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: r.URL.Hostname(),
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{r.URL.Hostname()},
	}

	serverCertBytes, err := x509.CreateCertificate(rand.Reader, &serverCertTemplate, caCert, &serverPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		log.Printf("Failed to create certificate", err)
		return tls.Certificate{}, err
	}

	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertBytes})
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverPrivateKey)})

	cert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		log.Printf("Failed to make pair for host", err)
		return tls.Certificate{}, err
	}

	return cert, nil
}

func handleHTTPS(w http.ResponseWriter, r *http.Request) {
	cert, err := getHostCert(r)
	if err != nil {
		http.Error(w, "Failed to make certificate", http.StatusInternalServerError)
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking is not available", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		log.Printf("Failed to send connection established response: %v", err)
		return
	}

	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("TLS handshake error: %v", err)
		return
	}
	defer tlsConn.Close()

	clientReq, err := http.ReadRequest(bufio.NewReader(tlsConn))
	if err != nil {
		log.Printf("Failed to read request %v", err)
		return
	}
	defer clientReq.Body.Close()
	//showRequest(clientReq)

	destConn, err := tls.Dial("tcp", r.Host, nil)
	if err != nil {
		log.Printf("Error connecting to host: %v", err)
		http.Error(w, "Failed to connect to server", http.StatusBadGateway)
		return
	}
	defer destConn.Close()

	err = clientReq.Write(destConn)
	if err != nil {
		log.Printf("Failed to write request to server: %v", err)
		return
	}

	serverResp, err := http.ReadResponse(bufio.NewReader(destConn), clientReq)
	if err != nil {
		log.Printf("Failed to read response from server: %v", err)
		return
	}

	err = serverResp.Write(tlsConn)
	if err != nil {
		log.Printf("Failed to write response back to client: %v", err)
		return
	}
}
