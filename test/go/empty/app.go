package main

import (
    "net/http"
    "nginx/unit"
)

func handler(w http.ResponseWriter, r *http.Request) {}

func main() {
    http.HandleFunc("/", handler)
    unit.ListenAndServe(":7080", nil)
}
