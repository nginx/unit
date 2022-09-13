# NGINX Unit

## Universal Web App Server

![NGINX Unit Logo](docs/unitlogo.svg)

NGINX Unit is a lightweight and versatile open-source server that has
three core capabilities:

- it is an HTTP reverse proxy,
- a web server for static media assets,
- and an application server that runs code in seven languages.

We are building a universal tool that compresses several layers of the modern
application stack into a potent, coherent solution with a focus on performance,
low latency, and scalability. It is intended as a building block for any web
architecture regardless of its complexity, from enterprise-scale deployments to
your pet's homepage.

Unit's native RESTful JSON API enables dynamic updates with zero interruptions
and flexible configuration, while its out-of-the-box productivity reliably
scales to production-grade workloads. We achieve that with a complex,
asynchronous, multithreading architecture comprising multiple processes to
ensure security and robustness while getting the most out of today's computing
platforms.


## Quick Installation

### macOS

``` console
$ brew install nginx/unit/unit
```

For details and available language packages, see the
[docs](https://unit.nginx.org/installation/#homebrew).


### Docker

``` console
$ docker pull docker.io/nginx/unit
```

For a description of image tags, see the
[docs](https://unit.nginx.org/installation/#docker-images).


### Amazon Linux, Fedora, RedHat

``` console
$ curl -sL 'https://unit.nginx.org/_downloads/setup-unit.sh' | sudo -E bash
# yum install unit
```

For details and available language packages, see the
[docs](https://unit.nginx.org/installation/#official-packages).


### Debian, Ubuntu

``` console
$ curl -sL 'https://unit.nginx.org/_downloads/setup-unit.sh' | sudo -E bash
# apt install unit
```

For details and available language packages, see the
[docs](https://unit.nginx.org/installation/#official-packages).


## Running a Hello World App

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

Now, `PUT` it into the `config/applications` section of Unit's control API,
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

Next, reference the app from a listener object in the `config/listeners`
section of the API.  This time, we pass the config snippet straight from the
command line:

``` console
# curl -X PUT -d '{"127.0.0.1:8000": {"pass": "applications/helloworld"}}'  \
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

For full details of configuration management, see the
[docs](https://unit.nginx.org/configuration/#configuration-management).


## Community

- The go-to place to start asking questions and share your thoughts is
  our [Slack channel](https://nginxcommunity.slack.com/).

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

- For security issues, [email us](security-alert@nginx.org), mentioning
  NGINX Unit in the subject and following the [CVSS
  v3.1](https://www.first.org/cvss/v3.1/specification-document) spec.

