package main

import (
	"fmt"
	"io"
	"net/http"
	"unit.nginx.org/go"
)

func handler(w http.ResponseWriter, r *http.Request) {
	var buf [32768]byte
	len, _ := r.Body.Read(buf[:])

	w.Header().Add("Content-Length", fmt.Sprintf("%v", len))
	io.WriteString(w, string(buf[:len]))
}

func main() {
	http.HandleFunc("/", handler)
	unit.ListenAndServe(":8080", nil)
}
