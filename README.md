<!-- menu -->

- [NGINX Unit](#nginx-unit)
  - [Key Features](#key-features)
  - [Supported Application Languages](#supported-application-languages)
- [Installation](#installation)
  - [System Requirements](#system-requirements)
  - [Precompiled Packages](#precompiled-packages)
    - [CentOS Packages](#centos-packages)
    - [Ubuntu Packages](#ubuntu-packages)
  - [Source Code](#source-code)
    - [Getting Sources](#getting-sources)
      - [Mercurial Repository](#mercurial-repository)
      - [GitHub Repository](#github-repository)
      - [Tarball](#tarball)
    - [Installing Required Software](#installing-required-software)
      - [Ubuntu Prerequisites](#ubuntu-prerequisits)
      - [CentOS Prerequisites](#centos-prerequisits)
    - [Configuring Sources](#configuring-sources)
      - [Configuring Go Package](#configuring-go-package)
      - [Building the Go Applications](#building-the-go-applications)
      - [Configuring PHP Modules](#configuring-php-modules)
      - [Configuring Python Modules](#configuring-python-modules)
    - [Compiling Sources](#compiling-sources)
    - [Installing from Sources](#installing-from-sources)
- [Configuration](#configuration)
  - [Applications](#applications)
  - [Listeners](#listeners)
  - [Minimum Configuration](#minimum-configuration)
  - [Creating Configuration Objects](#creating-configuration-objects)
    - [Example: Create a Full Configuration](#example-create-a-full-configuration)
    - [Example: Create an Application Object](#example-create-an-application-object)
  - [Displaying Configuration Objects](#displaying-configuration-objects)
    - [Example: Display the Full Configuration](#example-display-the-full-configuration)
    - [Example: Display One Object](#example-display-one-object)
  - [Modifying Configuration Objects](#modifying-configuration-objects)
    - [Example: Change the Application for a Listener](#example-change-the-application-for-a-listener)
    - [Example: Change the File Path for an Application](#example-change-the-file-path-for-an-application)
  - [Deleting Configuration Objects](#deleting-configuration-objects)
    - [Example: Delete a Listener](#example-delete-a-listener)
  - [Listener and Application Objects](#listener-and-application-objects)
    - [Listener](#listener)
    - [Go Application](#go-application)
    - [PHP Application](#php-application)
    - [Python Application](#python-application)
    - [Full Example](#full-example)
- [Integration with NGINX](#integration-with-nginx)
  - [Installing Unit Behind NGINX](#installing-unit-behind-nginx)
     - [Example 1](#installing-unit-example1)
     - [Example 2](#installing-unit-example2)
  - [Securing and Proxying Unit API](#securing-and-proxying-unit-api)
- [Contribution](#contribution)
- [Troubleshooting](#troubleshooting)

<!-- /menu -->

<!-- section:1 -->

## NGINX Unit

NGINX Unit is a dynamic web application server, designed to run applications
in multiple languages. Unit is lightweight, polyglot, and dynamically
configured via API. The design of the server allows reconfiguration of
specific application parameters as needed by the engineering or operations.

NGINX Unit is currently available as a beta. As such, it is suitable for use
in a testing environment, but is not recommended for use in production.

The sources are distributed under the Apache 2.0 license.

### Key Features

   * Fully dynamic reconfiguration using RESTful JSON API
   * Multiple application languages and versions can run simultaneously
   * Dynamic application processes management (coming soon)
   * TLS support (coming soon)
   * TCP, HTTP, HTTPS, HTTP/2 routing and proxying (coming soon)

### Supported Application Languages

   * Python
   * PHP
   * Go
   * JavaScript/Node.js (coming soon)
   * Java (coming soon)
   * Ruby (coming soon)

<!-- /section:1 -->

<!-- section:2 -->

## Installation

### System Requirements

NGINX Unit is tested to compile and run on the following systems:
   * Linux 2.6 or later
   * FreeBSD 9 or later
   * MacOS X
   * Solaris 11

Architectures:
   * i386
   * amd64
   * powerpc
   * arm

For applications running in NGINX Unit you need the respective programming
languages:
   * Python 2.6, 2.7, 3
   * PHP 5, 7
   * Go 1.6 or later

You can run multiple versions of the same language installed on the same
system.

### Precompiled Packages

Precompiled binaries for Unit are available for CentOS&nbsp;7.0 and
Ubuntu&nbsp;16.04&nbsp;LTS.

#### CentOS Packages

   1. Create the file **/etc/yum.repos.d/unit.repo** with the following
   contents:

   ```
   [unit]
   name=unit repo
   baseurl=http://nginx.org/packages/mainline/centos/7/$basearch/
   gpgcheck=0
   enabled=1
   ```

   2. Download the Unit package:

   ```
   # yum install unit
   ```

#### Ubuntu Packages

   1. Download the [key](http://nginx.org/keys/nginx_signing.key) used to sign
   the NGINX,&nbsp;Inc. repository and packages.

   2. Add the key to the `apt` program's keyring. The program can then
   authenticate the NGINX repository signature, which eliminates warnings
   about a missing PGP key during installation of the Unit package.

   ```
   # sudo apt-key add nginx_signing.key
   ```

   3. Append the following to the end of the file **/etc/apt/sources.list**:

   ```
   deb http://nginx.org/packages/mainline/ubuntu/ xenial nginx
   deb-src http://nginx.org/packages/mainline/ubuntu/ xenial nginx
   ```

   4. Download the Unit package:

   ```
   # apt-get update
   # apt-get install unit
   ```

### Source Code

This section explains how to compile and install Unit from the source code.

#### Getting Sources

There are three ways to obtain the Unit source code: from the NGINX,&nbsp;Inc.
Mercurial repository, from GitHub, or in a tarball.

In each case, the sources are placed in the **unit** subdirectory of the
current working directory.

##### Mercurial Repository

   1. If you don't already have the Mercurial software, download and install it.
   For example, on Ubuntu systems, run this command:

   ```
   # apt-get install mercurial
   ```

   2. Download the Unit sources:

   ```
   # hg clone http://hg.nginx.org/unit
   ```

##### GitHub Repository

   1. If you don't already have the Git software, download it. See the
   [GitHub documentation](https://help.github.com/).

   2. Download the Unit sources:

   ```
   # git clone https://github.com/nginx/unit
   ```

##### Tarball

Unit source code tarballs are available at
[http://unit.nginx.org/download/](http://unit.nginx.org/download/)

#### Installing Required Software

Before configuring and compiling Unit, you must install the required build
tools plus the library files for each of the available languages (Go, PHP,
and Python) that you want to support.

##### Ubuntu Prerequisites

   1. Install the build tools.

   ```
   # apt-get install build-essential
   ```

   2. For Go applications support, install the `golang` package. 

   ```
   # apt-get install golang
   ```

   3. For PHP applications support, install the `php-dev` and `libphp-embed`
   packages.

   ```
   # apt-get install php-dev
   # apt-get install libphp-embed
   ```

   4. For Python applications support, install the `python-dev` package.

   ```
   # apt-get install python-dev
   ```

##### CentOS Prerequisites

   1. Install the build tools.

   ```
   # yum install gcc make
   ```

   2. For Go applications support, install the `golang` package.

   ```
   # yum install golang
   ```

   3. For PHP applications support, install the `php-devel` and `php-embedded`
   packages.

   ```
   # yum install php-devel php-embedded
   ```

   4. For Python applications support, install the `python-devel` package.

   ```
   # yum install python-devel
   ```

#### Configuring Sources

With Unit, you can simultaneously run applications that use different versions
of a supported language (Go, PHP, or Python). You need to configure a separate
Unit module for each one. The following commands create the necessary
instructions in the **Makefile** for each module.

##### Configuring Go Package

NGINX Unit will provide the Go package that is required for running your Go
application inside Unit.

   1. Set the `GOPATH` environment variable, which sets the output directory
   for the Unit Go package.

   ```
   # export GOPATH=/home/user/go_apps
   ```

   2. Run the following command:

   ```
   # ./configure go
   configuring Go package
   checking for Go ... found
    + go version go1.6.2 linux/amd64
    + Go package path: "/home/user/go_apps"
   ```

##### Building the Go Applications

   1. Modify the source file for the Go application, making changes in two
   places:

       a. In the `import` section, add `"unit"` on a separate line.

      ```
      import {
          "fmt"
          "net/http"
          "unit"
      }
      ```

       b. In the `main()` function, comment out the `http.ListenandServe`
       function and insert the `unit.ListenAndServe` function.

      ```
      func main() {
           http.HandleFunc("/", handler)
           //http.ListenAndServe(":8080", nil)
           unit.ListenAndServe(":8080", nil)
      ```

   2. Build the Go application.

      ```
      # go build
      ```

If the Go application is executed directly, the unit module will fall back to
the http module. If the Go application is launched by Unit, it will communicate
with the Unit router via shared memory.

##### Configuring PHP Modules

To configure a Unit module (called **php.unit.so**) for the most recent version
of PHP that the `configure` script finds bundled with the operating system, run
this command:

```
# ./configure php
```

To configure Unit modules for other versions of PHP (including versions you
have customized), repeat the following command for each one:

```
# ./configure php --module=<prefix> --config=<script-name> --lib-path=<pathname>
```

where

   * `--module` sets the filename prefix for the Unit module specific
   to the PHP version (that is, the resulting module is called
   &lt;prefix&gt;.**unit.so**).

   * `--config` specifies the filename of the **php-config** script for the
   particular version of PHP.

   * `--lib-path` specifies the directory for the PHP library file to use.

For example, this command generates a module called **php70.unit.so** for
PHP&nbsp;7.0:

```
# ./configure php --module=php70  \
                  --config=/usr/lib64/php7.0/php-config  \
                  --lib-path=/usr/lib64/php7.0/lib64
configuring PHP module
checking for PHP ... found
 + PHP version: 7.0.22-0ubuntu0.16.04.1
 + PHP SAPI: [apache2handler embed cgi cli fpm]
checking for PHP embed SAPI ... found
 + PHP module: php70.unit.so
 ```

##### Configuring Python Modules

To configure a Unit module (called **python.unit.so**) for the most recent
version of Python that the `configure` script finds bundled with the operating
system, run this command.

```
# ./configure python
```

To configure Unit modules for other versions of Python (including versions you
have customized), repeat the following command for each one:

```
# ./configure python --module=<prefix> --config=<script-name>
```

where

   * `--module` sets the filename prefix for the Unit module specific
   to the Python version (that is, the resulting modules is called
   &lt;prefix&gt;.**unit.so**).

   * `--config` specifies the filename of the **python-config** script for the
   particular version of Python.

For example, this command generates a module called **py33.unit.so** for
Python&nbsp;3.3:

```
# ./configure python  --module=py33  \
                      --config=python-config-3.3
configuring Python module
checking for Python ... found
checking for Python version ... 3.3
 + Python module: py33.unit.so
```

#### Compiling Sources

To compile the Unit executable and all configured modules for PHP, Python, or
both, run this command:

```
# make all
```

To compile the packages for Go:

   1. Verify that the `GOPATH` environment variable is set correctly, or set
   the `GOPATH` variable.

   ```
   # go env GOPATH

   # export GOPATH=<path>
   ```

   2. Compile and install the package:

   ```
   # make go-install
   ```

#### Installing from Sources

To install Unit with all modules and Go packages, run the following command:

```
# make install
```

<!-- /section:2 -->

<!-- section:3 -->

## Configuration

By default, the Unit API is available in the control socket file
**unit.control.sock**.

### Applications

For each application, you use the API to define a JSON object in the
`applications` section of the Unit configuration. The JSON object defines
several characteristics of the application, including the language it's written
in, the number of application worker processes to run, the directory with
the file or files for the application, and parameters that vary by language.

This example runs three workers of the PHP application named **blogs** using the
files found in the **/www/blogs/scripts** directory. The default launch file
when the URL doesn't specify the PHP file is **index.php**.

   ```
   {
        ...
        "applications": {
            "blogs": {
                "type": "php",
                "workers": 20,
                "root": "/www/blogs/scripts",
                "index": "index.php"
            }
        }
   }
   ```

### Listeners

For an application to be accessible via HTTP, you must define at least
one listener for it in the `listeners` section of the Unit configuration. A
listener is an IP address and port on which Unit listens for client requests to
a named application. The IP address can be either a full address (for example,
`127.0.0.1:8300`) or a wildcard (for example, ``*:8300`).

In this example, requests received on port&nbsp;8300 are sent to the **blogs**
application:

    ```
    {
         "listeners": {
             "*:8300": {
                 "application": "blogs"
             }
         },
         ...
    }
    ```


For complete details about the JSON objects for each language, see
[JSON Specification for Listener and Application Objects](#json-specification-for-listener-and-application-objects).

### Minimum Configuration

The configuration must include at least one listener and associated
application, as in this example:

```
{
     "listeners": {
         "*:8300": {
             "application": "blogs"
         }
     },
     "applications": {
         "blogs": {
             "type": "php",
              "workers": 20,
              "root": "/www/blogs/scripts",
              "index": "index.php"
         }
     }
}
```

### Creating Configuration Objects

To create a configuration object, specify the JSON data for it in the body of
a `PUT` request. To reduce errors, it makes sense to write the JSON data in a
file and specify the file path with the `-d` option to the `curl` command.

#### Example: Create a Full Configuration

Create an initial configuration by uploading the contents of the **start.json**
file:

```
# curl -X PUT -d @/path/to/start.json  \
       --unix-socket ./control.unit.sock http://localhost/
```

#### Example: Create an Application Object

Create a new application object called **wiki** from the file **wiki.json**.

```
# curl -X PUT -d @/path/to/wiki.json  \
       --unix-socket ./control.unit.sock http://localhost/applications/wiki
```

The contents of **wiki.json** are:

```
{
    "type": "python",
    "workers": 10,
    "module": "wsgi",
    "user": "www-wiki",
    "group": "www-wiki",
    "path": "/www/wiki"
}
```

### Displaying Configuration Objects

To display a configuration object, append its path to the `curl` URL.

#### Example: Display the Full Configuration

Display the complete configuration:

```
# curl --unix-socket ./control.unit.sock http://localhost/
{
    "applications": {
       "blogs": {
          "type": "php",
          "user": "nobody",
          "group": "nobody",
          "workers": 20,
          "root": "/www/blogs/scripts",
          "index": "index.php"
       },

       "wiki": {
          "type": "python",
          "user": "nobody",
          "group": "nobody",
          "workers": 10,
          "path": "/www/wiki",
          "module": "wsgi"
       }
    },


   "listeners": {
      "*:8300": {
         "application": "blogs"
      },


      "*:8400": {
         "application": "wiki"
      }
   }
}
```

#### Example: Display One Object

Display the data for the **wiki** application:

```
# curl --unix-socket ./control.unit.sock http://localhost/applications/wiki
{
    "type": "python",
    "workers": 10,
    "module": "wsgi",
    "user": "www",
    "group": "www",
    "path": "/www/wiki"
}
```

### Modifying Configuration Objects

To change a configuration object, use the `-d` option to the `curl` command to
specify the object's JSON data in the body of a `PUT` request.

#### Example: Change the Application for a Listener

Change the `application` object to **wiki-dev** for the listener on *:8400:

```
# curl -X PUT -d '"wiki-dev"' --unix-socket ./control.unit.sock  \
       'http://localhost/listeners/*:8400/application'
{
    "success": "Reconfiguration done."
}
```

#### Example: Change the File Path for an Application

Change the `root` object for the **blogs** application to
**/www/blogs-dev/scripts**:

```
# curl -X PUT -d '"/www/blogs-dev/scripts"'  \
       --unix-socket ./control.unit.sock  \
       http://localhost/applications/blogs/root
{
    "success": "Reconfiguration done."
}
```

### Deleting Configuration Objects

To delete a configuration object, make a `DELETE` request and append the
object's path to the `curl` URL.

#### Example: Delete a Listener

Delete the listener on *:8400:

```
# curl -X DELETE --unix-socket ./control.unit.sock  \
       'http://localhost/listeners/*:8400'
{
    "success": "Reconfiguration done."
}
```

### Listener and Application Objects

#### Listener

|  Object | Description |
| --- | --- |
| `<IP-address>:<port>`          | IP address and port on which Unit listens for requests to the named application. The IP address can be either a full address (`127.0.0.1:8300`) or a wildcard (`*:8300`).
| `application`                  | Application name.

Example:

```
"*:8300": {
           "application": "blogs"
          }
```

#### Go Application

|  Object | Description |
| --- | --- |
| `type`| Type of the application (`go`).
| `workers`           | Number of application workers.
| `executable`        | Full path to compiled Go app.
| `user` (optional)   | Username that runs the app process. If not specified, `nobody` is used.
| `group` (optional)  | Group name that runs the app process. If not specified, user's primary group is used.

Example:

```
"go_chat_app": {
            "type": "go",
            "executable": "/www/chat/bin/chat_app",
            "user": "www-go",
            "group": "www-go"
        }
```

#### PHP Application

|  Object | Description |
| --- | --- |
| `type`| Type of the application (`php`).
| `workers`           | Number of application workers.
| `root`              | Directory to search for PHP files.
| `index`             | Default launch file when the PHP file name is not specified in the URL.
| `script` (optional) | File that Unit runs for every URL, instead of searching for a file in the filesystem. The location is relative to the root.
| `user` (optional)   | Username that runs the app process. If not specified, `nobody` is used.
| `group` (optional)  | Group name that runs the app process. If not specified, user's primary group is used.

Example:

```
"blogs": {
            "type": "php",
            "workers": 20,
            "root": "/www/blogs/scripts",
            "index": "index.php",
            "user": "www-blogs",
            "group": "www-blogs"
        },
```

#### Python Application

|  Object | Description |
| --- | --- |
| `type`| Type of the application (`python`).
| `workers`           | Number of application workers.
| `path`             | Path to search for the **wsgi.py** file.
| `module`             | Required. Currently the only supported value is `wsgi`.
| `user` (optional)   | Username that runs the app process. If not specified, `nobody` is used.
| `group` (optional)  | Group name that runs the app process. If not specified, user's primary group is used.

Example:

```
"shopping_cart": {
             "type": "python",
             "workers": 10,
             "path": "/www/store/cart",
             "module": "wsgi",
             "user": "www",
             "group": "www"
            },
```

#### Full Example

```
{
    "listeners": {
        "*:8300": {
            "application": "blogs"
        },
        "*:8400": {
            "application": "wiki"
        },
        "*:8401": {
            "application": "shopping_cart"
        },
        "*:8500": {
            "application": "go_chat_app"
        }
    },
    "applications": {
        "blogs": {
            "type": "php",
            "workers": 20,
            "root": "/www/blogs/scripts",
            "user": "www-blogs",
            "group": "www-blogs",
            "index": "index.php"
        },
        "wiki": {
            "type": "python",
            "workers": 10,
            "user": "www-wiki",
            "group": "www-wiki",
            "path": "/www/wiki"
        },
        "shopping_cart": {
            "type": "python",
            "workers": 10,
            "module": "wsgi",
            "user": "www",
            "group": "www",
            "path": "/www/store/cart"
        },
        "go_chat_app": {
            "type": "go",
            "user": "www-chat",
            "group": "www-chat",
            "executable": "/www/chat/bin/chat_app"
        }
    }
}
```

<!-- /section:3 -->

<!-- section:4 -->

## Integration with NGINX

### Installing Unit Behind NGINX

Configure NGINX as a static web server and reverse proxy in front of Unit.

NGINX serves static files directly from the filesystem, and the requests
to the applications are forwarded to Unit.

Create an upstream block in `http` context of NGINX configuration and add
Unit server IP and port to the upstream block, for example:

```
upstream unit_backend {
    server 127.0.0.1:8300;
}
```

Create or modify `server` and `location` blocks in `http` context of NGINX
configuration. Specify static files directory and the name of Unit upstream.

#### Example 1

For PHP applications, all requests with URLs ending in `.php` will be proxied
to Unit. All other files will be served directly by NGINX:


```
server {

    location / {
        root /var/www/static-data;
    }

    location ~ \.php$ {
        proxy_pass http://unit_backend;
        proxy_set_header Host $host;
    }
}
```

#### Example 2

For the following application, all static files need to be placed in
`/var/www/files` directory, and referenced by URLs starting with `/static`.
All other requests will be proxied to Unit:

```
 server {

    location /static {
        root /var/www/files;
    }

    location / {
        proxy_pass http://unit_backend;
        proxy_set_header Host $host;
    }
}
```

Refer to NGINX documentation at [http://nginx.org](http://nginx.org)
for more information.
Commercial support and advanced features are available at
[https://www.nginx.com](https://www.nginx.com)

### Securing and Proxying Unit API

By default, Unit API is available through a Unix domain socket. In order for
the API to be available remotely, configure a reverse proxy with NGINX.

NGINX can provide security, authentication, and access control to the API. It
is not recommended to expose unsecure Unit API.

Use the following configuration example for NGINX:

```
server {
    
    # Configure SSL encryption
    server 443 ssl;
    ssl_certificate /path/to/ssl/cert.pem;
    ssl_certificate_key /path/to/ssl/cert.key;

    # Configure SSL client certificate validation
    ssl_client_certificate /path/to/ca.pem;
    ssl_verify_client on;

    # Configure network ACLs
    #allow 1.2.3.4; # Uncomment and change to the IP addresses and networks
                    # of the administrative systems.
    deny all;

    # Configure HTTP Basic authentication
    auth_basic on;
    auth_basic_user_file /path/to/htpasswd.txt;

    location / {
        proxy_pass http://unix:/path/to/control.unit.sock
    }
}

```

<!-- /section:4 -->

<!-- section:5 -->

## Contribution

NGINX Unit is released under the Apache 2.0 license.

To contribute changes, either submit them by email to
[unit@nginx.org](mailto:unit@nginx.org) or submit a pull request in the
[https://github.com/nginx/unit](https://github.com/nginx/unit) repository.

<!-- /section:5 -->

<!-- section:6 -->

## Troubleshooting

Unit log for the binary packages is located in `/var/log/unit.log`.

Log file location can also be found by running `unitd --help`.

Debug verbosity level of the log is enabled during configuration time:

```
./configure --debug
```

Unit and all modules have to be recompiled and reinstalled after reconfiguring.

Please be aware that the debug log size grows very quickly.

Community mailing list is available at <unit@nginx.org>.
Subscribe to the mailing list by sending email to
[unit-subscribe@nginx.org](mailto:unit-subscribe@nginx.org)
or at [here](http://mailman.nginx.org/mailman/listinfo/unit).

<!-- /section:6 -->
