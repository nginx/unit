package main

import (
	"net/http"
	"unit.nginx.org/go"
)

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Var-1", r.URL.Query().Get("var1"))
	w.Header().Set("X-Var-2", r.URL.Query().Get("var2"))
	w.Header().Set("X-Var-3", r.URL.Query().Get("var3"))
}

func main() {
	http.HandleFunc("/", handler)
	unit.ListenAndServe(":8080", nil)
}
