# NGINX Unit Rust SDK and CLI

This project provides a Rust SDK interface to the
[NGINX Unit](https://unit.nginx.org/)
[control API](https://unit.nginx.org/howto/source/#source-startup)
and a CLI (`unitctl`) that exposes the functionality provided by the SDK.

## Installation and Use
In order to build and use `unitctl` one needs a working installation of
Cargo. It is recommended to procure Cargo with Rustup. Rustup is packaged
for use in many systems, but you can also find it at its
[Official Site](https://rustup.rs/). Additionally, Macintosh users will
need to install GNU core utilities using brew (see the following command)

```
$ brew install make gnu-sed grep gawk maven
```

After installing a modern distribution of Make, Macintosh users can invoke
the makefile commands using `gmake`. For example: `gmake clean` or `gmake all`.

Finally, in order to run the OpenAPI code generation tooling, Users will
need a working
[Java runtime](https://www.java.com/en/)
as well as Maven. Macintosh users can install Maven from Brew.

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

- Consumes alternative configuration formats Like YAML and converts them
- Syntactic highlighting of JSON output
- Interpretation of Unit errors with (arguably more) useful error messages

### Lists all running Unit processes and provides details about each process.
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

### Start a new Unit process via docker
```
$ unitctl instances new /tmp/2 $(pwd) 'unit:wasm'
Pulling and starting a container from unit:wasm
Will mount /tmp/2 to /var/run for socket access
Will READ ONLY mount /home/ava/repositories/nginx/unit/tools/unitctl to /www for application access
Note: Container will be on host network

```

To the subcommand `unitctl instances new` the user must provide three things:
1. **A directory such as `/tmp/2`.**
   The Unit container will mount this to `/var/run` internally.
   Thus, the control socket and pid file will be accessible from the host.
2. **A path to an application.**
   In the example, `$(pwd)` is provided. The Unit container will mount
   this READ ONLY to `/www/`. This will allow the user to configure
   their Unit container to expose an application stored on the host.
3. **An image tag.**
   In the example, `unit:wasm` is used. This will be the image that unitctl
   will deploy. Custom repos and images can be deployed in this manner.

After deployment the user will have one Unit container running on the host network.

### Lists active listeners from running Unit processes
```
unitctl listeners
No socket path provided - attempting to detect from running instance
{
  "127.0.0.1:8080": {
    "pass": "routes"
  }
}
```

### Get the current status of NGINX Unit processes
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

### Send arbitrary configuration payloads to Unit
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
