package main

import (
	"net/http"
	"unit.nginx.org/go"
)

func handler(w http.ResponseWriter, r *http.Request) {
	cookie1, _ := r.Cookie("var1")
	cookie2, _ := r.Cookie("var2")

	w.Header().Set("X-Cookie-1", cookie1.Value)
	w.Header().Set("X-Cookie-2", cookie2.Value)
}

func main() {
	http.HandleFunc("/", handler)
	unit.ListenAndServe(":8080", nil)
}
