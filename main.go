package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
)

func showRequest(r *http.Request) {
	dump, err := httputil.DumpRequest(r, true)
	if err != nil {
		fmt.Println("Error dumping request:", err)
		return
	}
	fmt.Println(string(dump))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	//r.Header.Del("Proxy-Connection")
	//showRequest(r)
	if r.Method == http.MethodConnect {
		handleHTTPS(w, r)
	} else {
		handleHTTP(w, r)
	}
}

func main() {
	server := &http.Server{
		Addr:    ":8080",
		Handler: http.HandlerFunc(handleRequest),
	}

	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Proxy listening on %s", server.Addr)
	log.Fatal(server.Serve(listener))
}
