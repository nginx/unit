package main

import (
	"fmt"
	"io"
	"net/http"
	"unit.nginx.org/go"
	"os"
	"strings"
)

func handler(w http.ResponseWriter, r *http.Request) {
	args := strings.Join(os.Args[1:], ",")

	w.Header().Add("X-Arg-0", fmt.Sprintf("%v", os.Args[0]))
	w.Header().Add("Content-Length", fmt.Sprintf("%v", len(args)))
	io.WriteString(w, args)
}

func main() {
	http.HandleFunc("/", handler)
	unit.ListenAndServe(":8080", nil)
}
