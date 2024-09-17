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
$ make list-targets
x86_64-unknown-linux-gnu

$ make x86_64-unknown-linux-gnu
▶ building unitctl with flags [--quiet --release --bin unitctl --target x86_64-unknown-linux-gnu]

$ file ./target/x86_64-unknown-linux-gnu/release/unitctl
./target/x86_64-unknown-linux-gnu/release/unitctl: ELF 64-bit LSB pie executable,
x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=ef4b094ffd549b39a8cb27a7ba2cc0dbad87a3bc, for GNU/Linux 4.4.0,
with debug_info, not stripped
```

As demonstrated in the example above, compiled binaries may be found in the
targets folder, under the subdirectory corresponding to the build target
desired.


## Features (Current)

```
CLI interface to the NGINX Unit Control API

Usage: unitctl [OPTIONS] <COMMAND>

Commands:
  instances  List all running Unit processes
  edit       Open current Unit configuration in editor
  import     Import configuration from a directory
  execute    Sends raw JSON payload to Unit
  status     Get the current status of Unit
  listeners  List active listeners
  apps       List all configured Unit applications
  export     Export the current configuration of Unit
  help       Print this message or the help of the given subcommand(s)

Options:
  -s, --control-socket-address <CONTROL_SOCKET_ADDRESS>
          Path (unix:/var/run/unit/control.sock), tcp address with port (127.0.0.1:80), or URL. This flag can be specified multiple times.
  -w, --wait-timeout-seconds <WAIT_TIME_SECONDS>
          Number of seconds to wait for control socket to become available
  -t, --wait-max-tries <WAIT_MAX_TRIES>
          Number of times to try to access control socket when waiting [default: 3]
  -h, --help
          Print help
  -V, --version
          Print version
```

- Consumes alternative configuration formats Like YAML and converts them
- Can convert output to multiple different formats (YAML, plain JSON, highlighted JSON)
- Syntactic highlighting of JSON output
- Interpretation of Unit errors with (arguably more) useful error messages

### Lists all running Unit processes and provides details about each process.
Unitctl will detect and connect to running process of Unit on the host.
It will pull information about the running Unit configuration
(including how to access its control API) from the process information of
each detected Unit process.

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
Unitctl can launch new containers of Unit.
These can be official Unit images or custom Unit images.
Any container that calls `unitd` in a CMD declaration will suffice.

The new containers will then be shown in a call to
`unitctl instances`

```
$ unitctl instances new /tmp/2 $(pwd) 'unit:wasm'
Pulling and starting a container from unit:wasm
Will mount /tmp/2 to /var/run for socket access
Will mount /home/user/repositories/nginx/unit/tools/unitctl to /www for application access
Note: Container will be on host network

```

To the subcommand `unitctl instances new` the user must provide three arguments:
1. **A means of showing the control API:**
   There are two possibilities for this argument.
   A filepath on which to open a unix socket,
   or a TCP address.
   - If a directory is specified the Unit container
     will mount this to `/var/run` internally.
     Thus, the control socket and pid file will be
     accessible from the host. For example: `/tmp/2`.
   - If a TCP endpoint is specified Unit will be configured
     to offer its control API on the given port and address.
     For example: `127.0.0.1:7171`.
2. **A path to an application:**
   In the example, `$(pwd)` is provided. The Unit container will mount
   this to `/www/`. This will allow the user to configure their
   Unit container to expose an application stored on the host.
3. **An image tag:**
   In the example, `unit:wasm` is used. This will be the image that unitctl
   will deploy. Custom repos and images can be deployed in this manner.

In addition to the above arguments, the user may add the `-r` flag. This flag will
set the Docker volume mount for the application directory to be read only. Do note
that this flag will break compatibility with WordPress, and other applications
which store state on the file system.

After deployment the user will have one Unit container running on the host network.

### Lists active applications and provides means to restart them
Unitctl can list running applications by accessing the specified control API.
Unitctl can also request from the API that an application be restarted.

Listing applications:
```
$ unitctl apps list
{
  "wasm": {
    "type": "wasm-wasi-component",
    "component": "/www/wasmapp-proxy-component.wasm"
  }
}
```

Restarting an application:
```
$ unitctl apps restart wasm
{
  "success": "Ok"
}
```

*Note:* Both of the above commands support operating on multiple instances
of Unit at once. To do this, pass multiple values for the `-s` flag as
shown below:

```
$ unitctl -s '127.0.0.1:8001' -s /run/nginx-unit.control.sock app list
```

### Lists active listeners from running Unit processes
Unitctl can query a given control API to fetch all configured
listeners.

```
unitctl listeners
No socket path provided - attempting to detect from running instance
{
  "127.0.0.1:8080": {
    "pass": "routes"
  }
}
```

*Note:* This command supports operating on multiple instances of Unit at once.
To do this, pass multiple values for the `-s` flag as shown below:

```
$ unitctl -s '127.0.0.1:8001' -s /run/nginx-unit.control.sock listeners
```

### Get the current status of NGINX Unit processes
Unitctl can query the control API to provide the status of the running
Unit daemon.

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

*Note:* This command supports operating on multiple instances of Unit at once.
To do this, pass multiple values for the `-s` flag as shown below:

```
$ unitctl -s '127.0.0.1:8001' -s /run/nginx-unit.control.sock status
```

### Send arbitrary configuration payloads to Unit
Unitctl can accept custom request payloads and query given API endpoints with them.
The request payload must be passed in using the `-f` flag either as a filename or
using the `-` filename to denote the use of stdin as shown in the example below.

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

*Note:* This command supports operating on multiple instances of Unit at once.
To do this, pass multiple values for the `-s` flag as shown below:

```
$ unitctl -s '127.0.0.1:8001' -s /run/nginx-unit.control.sock execute ...
```

### Edit current configuration in your favorite editor
Unitctl can fetch the configuration from a running instance of Unit and
load it in any number of preconfigured editors on your command line.

Unitctl will try to use whatever editor is configured with the `EDITOR`
environment variable, but will default to vim, emacs, nano, vi, or pico.

```
$ unitctl edit
[[EDITOR LOADS SHOWING CURRENT CONFIGURATION - USER EDITS AND SAVES]]

{
  "success": "Reconfiguration done."
}
```

*Note:* This command does not support operating on multiple instances of Unit at once.

### Import configuration, certificates, and NJS modules from directory
Unitctl will parse existing configuration, certificates, and NJS modules
stored in a directory and convert them into a payload to reconfigure a
given Unit daemon.

```
$ unitctl import /opt/unit/config
Imported /opt/unit/config/certificates/snake.pem -> /certificates/snake.pem
Imported /opt/unit/config/hello.js -> /js_modules/hello.js
Imported /opt/unit/config/put.json -> /config
Imported 3 files
```

### Export configuration from a running Unit instance
Unitctl will query a control API to fetch running configuration
and NJS modules from a Unit process. Due to a technical limitation
this output will not contain currently stored certificate bundles.
The output is saved as a tarball at the filename given with the `-f`
argument. Standard out may be used with `-f -` as shown in the
following examples.

```
$ unitctl export -f config.tar
$ unitctl export -f -
$ unitctl export -f - | tar xf - config.json
$ unitctl export -f - > config.tar
```

*Note:* The exported configuration omits certificates.

*Note:* This command does not support operating on multiple instances of Unit at once.

### Wait for socket to become available
All commands support waiting on unix sockets for availability.

```
$ unitctl --wait-timeout-seconds=3 --wait-max-tries=4 import /opt/unit/config`
Waiting for 3s control socket to be available try 2/4...
Waiting for 3s control socket to be available try 3/4...
Waiting for 3s control socket to be available try 4/4...
Timeout waiting for unit to start has been exceeded
```
