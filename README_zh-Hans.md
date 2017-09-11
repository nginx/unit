<!-- menu -->
[English](https://github.com/nginx/unit/blob/master/README.md)
[简体中文](https://github.com/tuzimoe/unit/blob/master/README_zh-Hans.md)
[繁體中文](https://github.com/tuzimoe/unit/blob/master/README_zh-Hant.md)
- [NGINX Unit](#nginx-unit)
  - [核心功能](#key-features)
  - [支持的开发语言](#supported-application-languages)
- [安装](#installation)
  - [系统需求](#system-requirements)
  - [预编译包](#precompiled-packages)
    - [CentOS 包](#centos-packages)
    - [Ubuntu 包](#ubuntu-packages)
  - [源代码](#source-code)
    - [获得源代码](#getting-sources)
      - [Mercurial 源](#mercurial-repository)
      - [GitHub 源](#github-repository)
      - [Tarball](#tarball)
    - [安装需要的软件](#installing-required-software)
      - [Ubuntu 依赖软件](#ubuntu-prerequisits)
      - [CentOS 依赖软件](#centos-prerequisits)
    - [配置源代码](#configuring-sources)
      - [配置Go语言包](#configuring-go-package)
      - [建立一个Go应用](#building-the-go-applications)
      - [配置PHP模块](#configuring-php-modules)
      - [配置Python模块](#configuring-python-modules)
    - [编译源代码](#compiling-sources)
    - [从源代码安装](#installing-from-sources)
- [配置](#configuration)
  - [应用](#applications)
  - [监听器](#listeners)
  - [最小化配置](#minimum-configuration)
  - [建立配置对象](#creating-configuration-objects)
    - [示例：一个完整的配置](#example-create-a-full-configuration)
    - [示例：创建一个应用](#example-create-an-application-object)
  - [显示配置的对象](#displaying-configuration-objects)
    - [示例：显示完整的配置](#example-display-the-full-configuration)
    - [示例：显示一个对象](#example-display-one-object)
  - [自定义对象的配置](#modifying-configuration-objects)
    - [示例：为监听器修改一个应用](#example-change-the-application-for-a-listener)
    - [示例：修改应用的文件路径](#example-change-the-file-path-for-an-application)
  - [删除配置的对象](#deleting-configuration-objects)
    - [示例：删除一个监听器](#example-delete-a-listener)
  - [监听器和应用对象](#listener-and-application-objects)
    - [监听器](#listener)
    - [Go语言应用](#go-application)
    - [PHP语言应用](#php-application)
    - [Python语言应用](#python-application)
    - [完整示例](#full-example)
- [和NGINX结合](#integration-with-nginx)
  - [在NGINX后安装单元](#installing-unit-behind-nginx)
     - [示例 1](#installing-unit-example1)
     - [示例 2](#installing-unit-example2)
  - [安全和代理单元的API](#securing-and-proxying-unit-api)
- [贡献](#contribution)
- [疑难解答](#troubleshooting)

<!-- /menu -->

<!-- section:1 -->

## NGINX Unit

NGINX Unit 是一个动态的网络应用服务器，它的设计初衷就是可运行多种编程语言的。通过API可以轻巧，多面化的动态配置Unit。当工程师或操作者有需要时，可以轻松重构服务器已适配特殊的应用参数。

NGINX Unit 现在是beta版本。你现在虽然可以使用它，但建议仅用于测试环境，不建议用于生产环境。

本项目的源代码及分发均使用Apache 2.0 license。

### 核心功能

   * 使用RESTful JSON API可完整的动态重配置服务器。
   * 可同时运行多语言及多版本的应用。
   * 动态语言的进程管理功能。 (敬请期待)
   * TLS 支持 (敬请期待)
   * TCP, HTTP, HTTPS, HTTP/2 路由和代理 (敬请期待)

### Supported Application Languages

   * Python
   * PHP
   * Go
   * JavaScript/Node.js (敬请期待)
   * Java (敬请期待)
   * Ruby (敬请期待)

<!-- /section:1 -->

<!-- section:2 -->

## 安装

### 系统需求

NGINX Unit 已被测试通过在以下系统上运行:
   * Linux 2.6 或更高
   * FreeBSD 9 或更高
   * MacOS X
   * Solaris 11

系统架构:
   * i386
   * amd64
   * powerpc
   * arm

NGINX Unit 支持不同的编程语言，你可以选择下面列出的版本:
   * Python 2.6, 2.7, 3
   * PHP 5, 7
   * Go 1.6 or later

你可以在一个系统上运行不同版本的相同编程语言。

### 安装包

你可以在CentOS&nbsp;7.0 和 Ubuntu&nbsp;16.04&nbsp;LTS。上直接安装 NGINX Next

#### CentOS 安装

   1. 在 **/etc/yum.repos.d/unit.repo** 目录下建立文件，并包含以下内容:

   ```
   [unit]
   name=unit repo
   baseurl=http://nginx.org/packages/mainline/centos/7/$basearch/
   gpgcheck=0
   enabled=1
   ```

   2. 安装Nginx Unit:

   ```
   # yum install unit
   ```

#### Ubuntu 安装

   1. 下载key [key](http://nginx.org/keys/nginx_signing.key) 用于签名NGINX,&nbsp;Inc. 的源和包。

   2. 添加秘钥到 `apt` 程序里。程序将会认证NGINX源的签名，这样将会消除警告。

   ```
   # sudo apt-key add nginx_signing.key
   ```

   3. 将下面两行写入文件尾部。
   **/etc/apt/sources.list**:

   ```
   deb http://nginx.org/packages/mainline/ubuntu/ xenial nginx
   deb-src http://nginx.org/packages/mainline/ubuntu/ xenial nginx
   ```

   4. 安装NGINX Unit:

   ```
   # apt-get update
   # apt-get install unit
   ```

### 源代码

本章将会完整的解释如何通过源代码安装NIGIX Unit。

#### 获得源代码

你可以通过三种方法获得NGINX Unit的源代码: 从 NGINX,&nbsp;Inc.
的Mercurial源，Github，或从tarball获得源代码。

无论从那种方式获得源代码，你均可以在 **unit** 子目录中，找到我们的源代码。

##### Mercurial源

   1. 如果你没有安装Mercurial软件。你需要先下载并安装它。
   示例：在 Ubuntu 系统下，运行下面的命令:

   ```
   # apt-get install mercurial
   ```

   2. 下载NIGIX Unit的源代码:

   ```
   # hg clone http://hg.nginx.org/unit
   ```

##### GitHub 源

   1. 如果你没有Git，请先移步Github帮助你安装Git
   [GitHub 帮助文档](https://help.github.com/)。

   2. 下载NGINX Unit源:

   ```
   # git clone https://github.com/nginx/unit
   ```

##### Tarball

NGINX Unit源代码请在以下链接获得
[http://unit.nginx.org/download/](http://unit.nginx.org/download/)

#### 安装依赖软件

在配置和安装 NGINX Unit 之前，你必须现安装依赖文件和必要的工具。以及你希望运行的编程语言。如 Go，PHP，和 Python。
##### Ubuntu 依赖安装

   1. 安装 build tools。

   ```
   # apt-get install build-essential
   ```

   2. 如果想支持Go语言应用，请安装 `golang` 包。

   ```
   # apt-get install golang
   ```

   3. 如果想支持PHP语言应用，请安装 `php-dev` 和 `libphp-embed` 包。

   ```
   # apt-get install php-dev
   # apt-get install libphp-embed
   ```

   4. 如果想支持Python语言应用，请安装 `python-dev` 包。

   ```
   # apt-get install python-dev
   ```

##### CentOS 依赖

   1. 安装 build tools。

   ```
   # yum install gcc make
   ```

   2. 如果想支持Go语言应用，请安装 `golang` 包。

   ```
   # yum install golang
   ```

   3. 如果想支持PHP语言应用，请安装 `php-devel` 和 `libphp-embedded` 包。

   ```
   # yum install php-devel php-embedded
   ```

   4. 如果想支持Python语言应用，请安装 `python-devel` 包。

   ```
   # yum install python-devel
   ```

#### 配置源代码

使用NGINX Unit，你可以同时运行不同版本的编程语言。（Go，PHP，或者Python）。你需要配置一个separate（分区）。
NGINX Unit有不同的模块。下面的命令会给不同的模块创建分区。 **Makefile**

##### 配置Go语言环境

NGINX Unit 会提供Go的依赖包，供你方便配置NGINX Unit内的Go使用环境。

   1. 使用下面的设置 `GOPATH` 的环境变量。

   ```
   # export GOPATH=/home/user/go_apps
   ```

   2. 运行以下命令:

   ```
   # ./configure go
   configuring Go package
   checking for Go ... found
    + go version go1.6.2 linux/amd64
    + Go package path: "/home/user/go_apps"
   ```

##### 建立Go应用

   1. 定义Go的源文件，以适应NGINX Unit。

       a. 在 `import` 区域，在尾行添加 `"unit"` 。

      ```
      import {
          "fmt"
          "net/http"
          "unit"
      }
      ```

       b. 在 `main()` 功能中， 注释 `http.ListenandServe`
       功能并添加 `unit.ListenAndServe` 功能。

      ```
      func main() {
           http.HandleFunc("/", handler)
           //http.ListenAndServe(":8080", nil)
           unit.ListenAndServe(":8080", nil)
      ```

   2. 建立 GO应用。

      ```
      # go build
      ```

如果你直接运行Go应用，Go将会自动使用http.ListenandServe。如果使用NGINX Unit，启动Go程序，将会自动执行unit.ListenandServe。程序将会与Unit的路由进行交互。

##### 配置PHP模块

配置PHP模块。( **php.unit.so**) 运行下面的命令进行自动配置PHP:

```
# ./configure php
```

如需要配置不同版本的PHP，请使用下面的命令:

```
# ./configure php --module=<prefix> --config=<script-name> --lib-path=<pathname>
```

当

   * `--module` 设置文件名的前缀。Unit被设置为特定的版本。( &lt;prefix&gt;.**unit.so**)。

   * `--config` 钦定的文件名， **php-config** 特定版本的PHP。

   * `--lib-path` PHP的路径。

实例：下面这个命令将会生成一个模块 **php70.unit.so** 已适配PHP7.0
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

##### 配置Python模块

配置特定的Python模块，已适配NGINX Unit。 (叫 **python.unit.so**) 。
在操作系统的根目录可以找到configure，使用下面的命令。

```
# ./configure python
```

如果需要配置其他的Python版本，请使用下面的命令。

```
# ./configure python --module=<prefix> --config=<script-name>
```

当

   * `--module` 会生成一个模块，设置文件名的前缀。Unit被设置为特定的版本， (就这么简单，将会生成一个
   &lt;prefix&gt;.**unit.so**).

   * `--config` 钦定的文件名 **python-config** 将会生成特定版本的模块。

示例：下面的命令将会生成一个名为 **py33.unit.so** 已适配
Python&nbsp;3.3:

```
# ./configure php --module=py33  \
                  --config=python-config-3.3
configuring Python module
checking for Python ... found
checking for Python version ... 3.3
 + Python module: py33.unit.so
```

#### 完成编译

当完成NGINX Unit的PHP, Python模块编译后, 运行下面的命令:

```
# make all
```

编译适用于Go语言的NGINX Unit:

   1. 确认`GOPATH` 环境变量已被正确设置。

   ```
   # go env GOPATH

   # export GOPATH=<path>
   ```

   2. 完成编译:

   ```
   # make go-install
   ```

#### 从源代码安装

如果需要安装完整的全面模块和Go包，运行下面的命令:

```
# make install
```

<!-- /section:2 -->

<!-- section:3 -->

## 配置

默认情况下，Control Socket内包含的的API来控制NGINX Unit
**unit.control.sock**.

### 应用

每个单独的应用，你都可以在NGINX Unit的配置文件中，使用JSON语法来定义一个
`applications`。使用JSON语法来定义里面的内容，如使用的编程语言，需要的工作数，文件的本地路径，以及其他参数。
这个示例配置了一个PHP网站，名为 **blogs** 而这个网站的本地路径为。 **/www/blogs/scripts**。默认页面为 **index.php**。

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

### 监听器

当应用被通过HTTP访问时，你必须定义至少一个监听器 `listeners`。监听器是一个IP地址和一个被定义的端口，当用户访问时，Unit的监听器会返回正确结果。IP地址可以是一个完整的IP地址(示例，
`127.0.0.1:8300`)或(示例，`*:8300`).

在这个示例中，端口&nbsp;8300 的请求全部会被发送至 **blogs**
这个应用:

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


完整的JSON语法细节，请点击下面的链接。
[JSON 详细的监听器配置和应用配置](#json-specification-for-listener-and-application-objects).

### 最小化配置

配置中至少需要包含一个监听器和一个应用配置:

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

### 创建配置文件

你可以创建一个配置文件，并且发送一个 `PUT` 请求。为了减少发生错误的可能，当使用 `curl` 命令式，请包含 `-d` 选项。

#### 示例：创建一个完整的配置文件

通过下面的命令，可以创建一个初始的配置文件
**start.json** :

```
# curl -X PUT -d @/path/to/start.json  \
       --unix-socket ./control.unit.sock http://localhost/
```

#### 示例：新建一个应用对象

通过 **wiki.json** 我们可以创建一个 **wiki** 应用。

```
# curl -X PUT -d @/path/to/wiki.json  \
       --unix-socket ./control.unit.sock http://localhost/applications/wiki
```

**wiki.json** 里包含了：

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

### 显示配置的对象

要显示配置的对象，它被附加在`curl` 的URL内。

#### 示例：显示完整的配置文件

如果你想显示完整的配置文件，你可以通过下面的指令来查看：

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

#### 示例：显示一个对象

显示 **wiki** 这个应用的配置，只需：

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

### 修改配置的对象：

要更改配置的对象，使用 `curl` 命令和`-d` 选项来实现特定的对象的JSON数据，然后发送一个`PUT`请求。

#### 示例：修改监听端口指向的应用

在端口 *:8400上修改 `application` 应用指向 **wiki-dev**：

```
# curl -X PUT -d '"wiki-dev"' --unix-socket ./control.unit.sock  \
       'http://localhost/listeners/*:8400/application'
{
    "success": "Reconfiguration done."
}
```

#### 示例：修改应用的本地路径

修改`root`对象的 **blogs** 应用的本地路径至
**/www/blogs-dev/scripts**:

```
# curl -X PUT -d '"/www/blogs-dev/scripts"'  \
       --unix-socket ./control.unit.sock  \
       http://localhost/applications/blogs/root
{
    "success": "Reconfiguration done."
}
```

### 删除对象

要删除配置的对象，你可以通过 `curl` 发送一个`DELETE` 请求到对象目录。

#### 示例：删除监听器

删除对 *:8400 端口的监听：

```
# curl -X DELETE --unix-socket ./control.unit.sock  \
       'http://localhost/listeners/*:8400'
{
    "success": "Reconfiguration done."
}
```

### 监听器和应用对象

#### 监听器

|  对象 | 描述 |
| --- | --- |
| `<IP地址>:<端口>`          | IP地址和端口需在不同的Unit监听器上均需要配置应用的名字 ，IP地址可以是完整的 (`127.0.0.1:8300`) 或者(`*:8300`).
| `application` | 应用名。

示例：

```
"*:8300": {
           "application": "blogs"
          }
```

#### Go语言应用

|  对象 | 描述 |
| --- | --- |
| `type`| 应用的编程语言 (`go`)。
| `workers`           | 应用的工作数量。
| `executable`        | 完整的本地路径。
| `user` (optional)   | 运行进程的用户，如未定义，则默认（nobody）。
| `group` (optional)  | 用户所在的用户组 。如未定义，则默认。

示例:

```
"go_chat_app": {
            "type": "go",
            "executable": "/www/chat/bin/chat_app",
            "user": "www-go",
            "group": "www-go"
        }
```

#### PHP语言应用

|  对象 | 描述 |
| --- | --- |
| `type`| 应用的编程语言 (`php`).
| `workers`           | 应用的工作数量。
| `root`              | 文件的本地路径。
| `index`             | 默认的index文件路径。
| `script` (optional) | 访问Unit内任意的URL均会运行，填写路径将不要填写物理路径，请填写虚拟路径。
| `user` (optional)   | 运行进程的用户，如未定义，则默认（nobody）。
| `group` (optional)  | 用户所在的用户组 。如未定义，则默认。

示例：

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

#### Python语言应用

|  Object | Description |
| --- | --- |
| `type`| 应用的编程语言 (`python`)。
| `workers`           | 应用的工作数量。
| `path`             | **wsgi.py** 的路径。
| `module`             | 必填。目前只支持 `wsgi`。
| `user` (optional)   | 运行进程的用户，如未定义，则默认（nobody）。
| `group` (optional)  | 用户所在的用户组 。如未定义，则默认。

示例：

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

#### 完整示例：

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

## NGINX一起使用

### 和NGINX一起使用

配置NGINX来进行静态文件的处理和接受代理的请求。
NGINX服务器将直接处理静态文件的访问请求，动态文件的处理将会直接转发到NGINX Unit。
新建一个上传模块，在NGINX的配置中，将http的请求转发给Unit，示例：
```
upstream unit_backend {
    server 127.0.0.1:8300;
}
```

新建或修改NGINX的配置文件 `server`块和 `location`块 。指定的静态文件的路径和上传模块。
#### 示例 1

这个例子适用于基于PHP编程语言开发的程序。，全部的URL请求，如已.php结尾，均会被转发至Unit服务器，其他的全部文件将会直接被服务器返回文件：

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

#### 示例 2

All other requests will be proxied to Unit:
下面的应用，全部都静态文件需要被放置在`/var/www/files` 目录下，在前端调用时，请直接使用`/static`。
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


相关的NGINX 文档将会在[http://nginx.org](http://nginx.org)提供。
相关的支持和更多的功能将在[https://www.nginx.com](https://www.nginx.com)上提供。

### 安全和代理Unit API

默认情况下，Unit的API将会在Unix domain socket下。如果你希望API可以被远程访问，你需要使用NGINX配置代理。
NGINX 可以提供安全的、可信的和可控制的API
使用下面的示例配置来配置NGINX：

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

## 贡献

NGINX Unit的发布和分发均使用Apache 2.0 license。
如果想贡献自己的力量，你可以选择通过邮件[unit@nginx.org](mailto:unit@nginx.org)
或者在Github上提交PR[https://github.com/nginx/unit](https://github.com/nginx/unit)。
如果在中文翻译方面需要改近请联系[@tuzimoe](https://github.com/tuzimoe)。
<!-- /section:5 -->

<!-- section:6 -->

## 疑难解答

Unit 日志一般在默认的位置，可以在`/var/log/unit.log` 中找到。
Log 文件的位置也可以通过运行 `unitd --help` 来快速定位。
详细的Debug日志可以通过输入命令来获得：
```
./configure --debug
```

输入完命令后，请务必重新编译和重装NGINX Unit。
请注意，debug日志的内容将会以快速的增长。

社区邮箱的列表将会在<unit@nginx.org>上找到。
订阅邮箱列表，可以通过发送任何内容至订阅
[unit-subscribe@nginx.org](mailto:unit-subscribe@nginx.org)
或直接点击此处订阅
[没错就是我](http://mailman.nginx.org/mailman/listinfo/unit)。



<!-- /section:6 -->
