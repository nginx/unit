package main

import (
	"fmt"
	"io"
	"net/http"
	"unit.nginx.org/go"
)

func handler(w http.ResponseWriter, r *http.Request) {
	var buf [4096]byte
	len, _ := r.Body.Read(buf[:])

	w.Header().Set("Request-Method", r.Method)
	w.Header().Set("Request-Uri", r.RequestURI)
	w.Header().Set("Server-Protocol", r.Proto)
	w.Header().Set("Server-Protocol-Major", fmt.Sprintf("%v", r.ProtoMajor))
	w.Header().Set("Server-Protocol-Minor", fmt.Sprintf("%v", r.ProtoMinor))
	w.Header().Set("Content-Length", fmt.Sprintf("%v", len))
	w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
	w.Header().Set("Custom-Header", r.Header.Get("Custom-Header"))
	w.Header().Set("Http-Host", r.Header.Get("Host"))

	io.WriteString(w, string(buf[:len]))
}

func main() {
	http.HandleFunc("/", handler)
	unit.ListenAndServe(":8080", nil)
}
