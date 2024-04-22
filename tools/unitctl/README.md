# NGINX UNIT Rust SDK and CLI

This project provides a Rust SDK interface to the
[NGINX UNIT](https://unit.nginx.org/)
[control API](https://unit.nginx.org/howto/source/#source-startup)
and a CLI (`unitctl`) that exposes the functionality provided by the SDK.

## Installation and Use
In order to build and use `unitctl` one needs a working installation of Maven
and Cargo. It is recommended to procure Cargo with Rustup. Rustup is packaged
for use in many systems, but you can also find it at its
[Official Site](https://rustup.rs/).

With a working installation of Cargo it is advised to build unitctl with the
provided makefile. The `list-targets` target will inform the user of what
platforms are available to be built. One or more of these can then be run as
their own makefile targets. Alternatively, all available binary targets can be
built with `make all`. See the below example for illustration:

```
[ava@calliope cli]$ make list-targets
x86_64-unknown-linux-gnu
[ava@calliope cli]$ make x86_64-unknown-linux-gnu
▶ building unitctl with flags [--quiet --release --bin unitctl --target x86_64-unknown-linux-gnu]
[ava@calliope cli]$ file ./target/x86_64-unknown-linux-gnu/release/unitctl
./target/x86_64-unknown-linux-gnu/release/unitctl: ELF 64-bit LSB pie executable,
x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=ef4b094ffd549b39a8cb27a7ba2cc0dbad87a3bc, for GNU/Linux 4.4.0,
with debug_info, not stripped
```

As demonstrated in the example above, compiled binaries may be found in the
targets folder, under the subdirectory corresponding to the build target
desired.


## Features (Current)

### Consumes alternative configuration formats Like YAML and converts them
### Syntactic highlighting of JSON output
### Interpretation of UNIT errors with (arguably more) useful error messages

### Lists all running UNIT processes and provides details about each process.
```
$ unitctl instances
No socket path provided - attempting to detect from running instance
unitd instance [pid: 79489, version: 1.32.0]:
  Executable: /opt/unit/sbin/unitd
  API control unix socket: unix:/opt/unit/control.unit.sock
  Child processes ids: 79489, 79489
  Runtime flags: --no-daemon
  Configure options: --prefix=/opt/unit --user=elijah --group=elijah --openssl
```

### Lists active listeners from running UNIT processes
```
unitctl listeners
No socket path provided - attempting to detect from running instance
{
  "127.0.0.1:8080": {
    "pass": "routes"
  }
}
```

### Get the current status of NGINX UNIT processes
```
$ unitctl status -t yaml
No socket path provided - attempting to detect from running instance
connections:
  accepted: 0
  active: 0
  idle: 0
  closed: 0
requests:
  total: 0
applications: {}
```

### Send arbitrary configuration payloads to UNIT
```
$ echo '{
    "listeners": {
        "127.0.0.1:8080": {
            "pass": "routes"
        }
    },

    "routes": [
        {
            "action": {
                "share": "/www/data$uri"
            }
        }
    ]
}' | unitctl execute --http-method PUT --path /config -f -
{
  "success": "Reconfiguration done."
}
```

### Edit current configuration in your favorite editor
```
$ unitctl edit
[[EDITOR LOADS SHOWING CURRENT CONFIGURATION - USER EDITS AND SAVES]]

{
  "success": "Reconfiguration done."
}
```

### Display interactive OpenAPI control panel
```
$ unitctl ui
Starting UI server on http://127.0.0.1:3000/control-ui/
Press Ctrl-C to stop the server
```

### Import configuration, certificates, and NJS modules from directory
```
$ unitctl import /opt/unit/config
Imported /opt/unit/config/certificates/snake.pem -> /certificates/snake.pem
Imported /opt/unit/config/hello.js -> /js_modules/hello.js
Imported /opt/unit/config/put.json -> /config
Imported 3 files
```
### Wait for socket to become available
```
$ unitctl --wait-timeout-seconds=3 --wait-max-tries=4 import /opt/unit/config`
Waiting for 3s control socket to be available try 2/4...
Waiting for 3s control socket to be available try 3/4...
Waiting for 3s control socket to be available try 4/4...
Timeout waiting for unit to start has been exceeded
```