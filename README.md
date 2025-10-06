# NGINX Unit

[![Project Status: Unsupported – The project has reached a stable, usable state, but the author(s) have ceased all work on it. A new maintainer is desired.](https://www.repostatus.org/badges/latest/unsupported.svg)](https://www.repostatus.org/#unsupported)

## Note: This repository has been archived. There will likely be no further development at this repo, and security vulnerabilities may be unaddressed.
## The repo may be cloned and used under its current license.


## Universal Web App Server

![NGINX Unit Logo](docs/unitlogo.svg)

NGINX Unit is a lightweight and versatile open-source server that has
two primary capabilities:

- serves static media assets,
- runs application code in eight languages.

Unit compresses several layers of the modern application stack into a potent,
coherent solution with a focus on performance, low latency, and scalability. It
is intended as a universal building block for any web architecture, regardless
of its complexity, from enterprise-scale deployments to your pet's homepage.

Its native [RESTful JSON API](#openapi-specification) enables dynamic
updates with zero interruptions and flexible configuration, while its
out-of-the-box productivity reliably scales to production-grade workloads. We
achieve that with a complex, asynchronous, multithreading architecture
comprising multiple processes to ensure security and robustness while getting
the most out of today's computing platforms.

## Installation

### macOS

Run the following command to install both `unitd` (the Unit daemon) and
`unitctl` (the control tool).

``` console
$ brew install nginx/unit/unit
```

For details and available language packages, see the
[docs](https://unit.nginx.org/installation/#homebrew).

### Docker

``` console
$ docker pull unit:<TAG>
$ mkdir /tmp/unit-control # customize as needed.
$ docker run -d \
      --mount type=bind,src=/tmp/unit-control,dst=/var/run \
      --mount type=bind,src=.,dst=/www \
      --network host \
      unit
```

For a description of image tags, see the
[docs](https://unit.nginx.org/installation/#docker-images).

WARNING: The latest image tag may not provide support for specific languages
modules, *do* check the available image tags from the link above before
pulling your image.

Your current working directory will now be mounted to the Unit image at `/www`.
You can reach its socket at `/tmp/unit-control/control.unit.sock` assuming no
further customizations have been made.

### Debian, Ubuntu, Amazon Linux, Fedora, Red Hat

This helper script configures the correct package repositories for system.
``` console
$ wget https://raw.githubusercontent.com/nginx/unit/master/tools/setup-unit && chmod +x setup-unit
# ./setup-unit repo-config
```

Debian derivatives:
``` console
# apt install unit
```

Fedora derivatives:
``` console
# yum install unit
```

For details and available language packages, see the
[docs](https://unit.nginx.org/installation/#official-packages).

## Getting Started with `unitctl`

[`unitctl`](tools/README.md) streamlines the management of NGINX Unit processes
through an easy-to-use command line interface. To get started with `unitctl`,
download it from the
[official GitHub releases](https://github.com/nginx/unit/releases)
or [Homebrew](#macos).

### Installation

> [!NOTE]
> If you installed Unit with [Homebrew](#macos), you can skip this step
> as `unitctl` is included by default.

Download the appropriate `unitctl` binary for your system from the
[NGINX Unit releases](https://github.com/nginx/unit/releases/).

``` console
$ tar xzvf unitctl-master-x86_64-unknown-linux-gnu.tar.gz
# mv unitctl /usr/local/bin/
```


## Launch Unit using Docker
If you have [Docker installed](https://docs.docker.com/engine/install/) on
your machine, and then you can effortlessly spin up one of
[Unit's official Docker images](https://hub.docker.com/_/unit)
alongside your application.

> [!TIP]
> How-to and configuration guides are available on
[unit.nginx.org](https://unit.nginx.org/howto/) for web application frameworks
built with Python, PHP, WebAssembly, Node.js, Ruby, and more.

Here's an example using the `unit:python` Docker image:
``` console
$ unitctl instances new 127.0.0.1:8001 /path/to/app 'unit:python'
```

`/path/to/app` will mount to `/www` in the Docker filesystem.

Save this to `/path/to/app/wsgi.py`:
```python
def application(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])
    return (b"Hello, Python on Unit!")
```

You can then interactively edit the currently active configuration:
``` console
$ unitctl edit
```
```jsonc
{
  "listeners": {
    "*:8000": {
      // Point listener to new application
      "pass": "applications/python"
    }
  },

  // Add an application definition
  "applications": {
    "python": {
        "type": "python",
        "path": "/www/",
        "module": "wsgi"
    }
  }
}
```
Valid configurations will be applied upon save and close.

``` console
$ curl localhost:8000

Hello, Python on Unit!
```
More Python configuration examples can be found in the
[Unit docs](https://unit.nginx.org/howto/samples/#python).

## Hello World with PHP and curl

Unit runs apps in a
[variety of languages](https://unit.nginx.org/howto/samples/).
Let's explore the configuration of a simple PHP app on Unit with `curl`.

Suppose you saved a PHP script as `/www/helloworld/index.php`:
``` php
<?php echo "Hello, PHP on Unit!"; ?>
```

To run it on Unit with the `unit-php` module installed, first set up an
application object. Let's store our first config snippet in a file called
`config.json`:

``` json
{
    "helloworld": {
        "type": "php",
        "root": "/www/helloworld/"
    }
}
```

Saving it as a file isn't necessary, but can come in handy with larger objects.

Now, `PUT` it into the `/config/applications` section of Unit's control API,
usually available by default via a Unix domain socket:

``` console
# curl -X PUT --data-binary @config.json --unix-socket  \
       /path/to/control.unit.sock http://localhost/config/applications
```
``` json
{
	"success": "Reconfiguration done."
}
```

Next, reference the app from a listener object in the `/config/listeners`
section of the API.  This time, we pass the config snippet straight from the
command line:

``` console
# curl -X PUT -d '{"127.0.0.1:8080": {"pass": "applications/helloworld"}}'  \
       --unix-socket /path/to/control.unit.sock http://localhost/config/listeners
```
``` json
{
    "success": "Reconfiguration done."
}
```

Now Unit accepts requests at the specified IP and port, passing them to the
application process. Your app works!

``` console
$ curl 127.0.0.1:8080

      Hello, PHP on Unit!
```

Finally, query the entire `/config` section of the control API:

``` console
# curl --unix-socket /path/to/control.unit.sock http://localhost/config/
```

Unit's output should contain both snippets, neatly organized:

``` json
{
    "listeners": {
        "127.0.0.1:8080": {
            "pass": "applications/helloworld"
        }
    },

    "applications": {
        "helloworld": {
            "type": "php",
            "root": "/www/helloworld/"
        }
    }
}
```

## WebAssembly
Unit supports running WebAssembly Components (WASI 0.2).
For more information see the
[Unit Configuration Docs](https://unit.nginx.org/configuration/#configuration-wasm).

## OpenAPI Specification

Our [OpenAPI specification](docs/unit-openapi.yaml) aims to simplify
configuring and integrating NGINX Unit deployments and provide an authoritative
source of knowledge about the control API.

## Community

- The go-to place to start asking questions and share your thoughts is
 [GitHub Discussions](https://github.com/nginx/unit/discussions).

- Our [GitHub issues page](https://github.com/nginx/unit/issues) offers
  space for a more technical discussion at your own pace.

- The [project map](https://github.com/orgs/nginx/projects/1) on
  GitHub sheds some light on our current work and plans for the future.

- Our [official website](https://unit.nginx.org/) may provide answers
  not easily found otherwise.

- Get involved with the project by contributing! See the
  [contributing guide](CONTRIBUTING.md) for details.

- To reach the team directly, subscribe to the
  [mailing list](https://mailman.nginx.org/mailman/listinfo/unit).

- For security issues, [email us](mailto:security-alert@nginx.org),
  mentioning NGINX Unit in the subject and following the [CVSS
  v3.1](https://www.first.org/cvss/v3.1/specification-document) spec.
