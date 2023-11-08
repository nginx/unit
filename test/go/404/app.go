package main

import (
	"io"
	"io/ioutil"
	"net/http"
	"unit.nginx.org/go"
)

func handler(w http.ResponseWriter, r *http.Request) {
	b, e := ioutil.ReadFile("404.html")

	if e == nil {
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, string(b))
	}
}

func main() {
	http.HandleFunc("/", handler)
	unit.ListenAndServe(":8080", nil)
}
