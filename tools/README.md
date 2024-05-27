# Unit Tools

This directory contains useful tools for installing, configuring, and
managing NGINX Unit. They may not be part of official packages and
should be considered experimental.

* [`setup-unit`](#setup-unit)
* [`unitc`](#unitc)
* [`unitctl`](#unitctl)

---

## setup-unit

### A script that simplifies installing and configuring an NGINX Unit server for first-time users

* `setup-unit repo-config` configures your package manager with the NGINX
Unit repository for later installation.
* `setup-unit welcome` creates an initial configuration to serve a welcome
web page with NGINX Unit.

---

## unitc

### A curl wrapper for managing NGINX Unit configuration

```USAGE: unitc [options] URI```

 * **URI** specifies the target in Unit's control API, e.g. `/config` .
 * Configuration data is read from stdin.
 * [jq](https://stedolan.github.io/jq/) is used to prettify JSON output, if
   available.

| Options | |
|---------|-|
| filename … | Read configuration data consecutively from the specified files instead of stdin.
| _HTTP method_ | It is usually not required to specify a HTTP method. `GET` is used to read the configuration. `PUT` is used when making configuration changes unless a specific method is provided.
| `edit` | Opens **URI** in the default editor for interactive configuration. The [jq](https://stedolan.github.io/jq/) tool is required for this option.
| `INSERT` | A _virtual_ HTTP method that prepends data when the URI specifies an existing array. The [jq](https://stedolan.github.io/jq/) tool is required for this option.
| `-f` \| `--format YAML` | Convert configuration data to/from YAML format. The [yq](https://github.com/mikefarah/yq) tool is required for this option.
| `-q` \| `--quiet` | No output to stdout.

Options are case insensitive and can appear in any order. For example, a
redundant part of the configuration can be identified by its URI, and
followed by `delete` in a subsequent command.

Options may be combined. For example, `edit -f yaml` will open the
configuration URI in a text editor, in YAML format.

### Local Configuration
For local instances of Unit, the control socket is automatically detected.
The error log is monitored; when changes occur, new log entries are shown.

| Options | |
|---------|-|
| `-l` \| `--nolog` | Do not monitor the error log after configuration changes.

#### Local Examples
```shell
unitc /config
unitc /config < unitconf.json
echo '{"*:8080": {"pass": "routes"}}' | unitc /config/listeners
unitc /config/applications/my_app DELETE
unitc /certificates/bundle cert.pem key.pem
```

### Remote Configuration
For remote instances of NGINX Unit, the control socket on the remote host can
be set with the `$UNIT_CTRL` environment variable. The remote control socket
can be accessed over TCP, SSH, or Docker containers on the host, depending on
the type of control socket:

 * `ssh://[user@]remote_host[:ssh_port]/path/to/control.socket`
 * `http://remote_host:unit_control_port`
 * `docker://container_ID[/path/to/control.socket]`

> **Note:** SSH is recommended for remote confguration. Consider the
> [security implications](https://unit.nginx.org/howto/security/#secure-socket-and-state)
> of managing remote configuration over plaintext HTTP.

| Options | |
|---------|-|
| `ssh://…` | Specify the remote Unix control socket on the command line.
| `http://…`*URI* | For remote TCP control sockets, the URI may include the protocol, hostname, and port.
| `docker://…` | Specify the local container ID/name. The default Unix control socket can be overridden.

#### Remote Examples
```shell
unitc http://192.168.0.1:8080/status
UNIT_CTRL=http://192.168.0.1:8080 unitc /status

export UNIT_CTRL=ssh://root@unithost/var/run/control.unit.sock
unitc /config/routes
cat catchall_route.json | unitc POST /config/routes
echo '{"match":{"uri":"/wp-admin/*"},"action":{"return":403}}' | unitc INSERT /config/routes
```

#### Docker Examples
```shell
unitc docker://d43251184c54 /config
echo '{"http": {"log_route": true}}' | unitc docker://d43251184c54 /settings
unitc docker://f4f3d9e918e6/root/unit.sock /control/applications/my_app/restart
UNIT_CTRL=docker://4d0431488982 unitc /status/requests/total
```

---

## unitctl

### NGINX Unit Rust SDK and unitctl CLI

This project provides a Rust SDK interface to the
[NGINX UNIT](https://unit.nginx.org/)
[control API](https://unit.nginx.org/howto/source/#source-startup)
and a CLI (`unitctl`) that exposes the functionality provided by the SDK.

---
