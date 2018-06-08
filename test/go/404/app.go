package main

import (
    "io"
    "io/ioutil"
    "net/http"
    "nginx/unit"
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
    unit.ListenAndServe(":7080", nil)
}
