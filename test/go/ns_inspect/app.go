package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"unit.nginx.org/go"
	"os"
	"strconv"
	"io/ioutil"
)

type (
	NS struct {
		USER   uint64
		PID    uint64
		IPC    uint64
		CGROUP uint64
		UTS    uint64
		MNT    uint64
		NET    uint64
	}

	Output struct {
		PID        int
		UID        int
		GID        int
		NS         NS
		FileExists bool
		Mounts     string
	}
)

func abortonerr(err error) {
	if err != nil {
		panic(err)
	}
}

// returns: [nstype]:[4026531835]
func getns(nstype string) uint64 {
	str, err := os.Readlink(fmt.Sprintf("/proc/self/ns/%s", nstype))
	if err != nil {
		return 0
	}

	str = str[len(nstype)+2:]
	str = str[:len(str)-1]
	val, err := strconv.ParseUint(str, 10, 64)
	abortonerr(err)
	return val
}

func handler(w http.ResponseWriter, r *http.Request) {
	pid := os.Getpid()
	out := &Output{
		PID: pid,
		UID: os.Getuid(),
		GID: os.Getgid(),
		NS: NS{
			PID:    getns("pid"),
			USER:   getns("user"),
			MNT:    getns("mnt"),
			IPC:    getns("ipc"),
			UTS:    getns("uts"),
			NET:    getns("net"),
			CGROUP: getns("cgroup"),
		},
	}

	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if fname := r.Form.Get("file"); fname != "" {
		_, err = os.Stat(fname);
		out.FileExists = err == nil
	}

	if mounts := r.Form.Get("mounts"); mounts != "" {
		data, _ := ioutil.ReadFile("/proc/self/mountinfo")
		out.Mounts = string(data)
	}

	data, err := json.Marshal(out)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")

	w.Write(data)
}

func main() {
	http.HandleFunc("/", handler)
	unit.ListenAndServe(":8080", nil)
}
