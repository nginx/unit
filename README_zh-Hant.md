<!-- menu -->
[English](https://github.com/nginx/unit/blob/master/README.md)
[简体中文](https://github.com/tuzimoe/unit/blob/master/README_zh-Hans.md)
[繁體中文](https://github.com/tuzimoe/unit/blob/master/README_zh-Hant.md)
- [NGINX Unit](#nginx-unit)
  - [核心功能](#key-features)
  - [支持的開發語言](#supported-application-languages)
- [安裝](#installation)
  - [系統需求](#system-requirements)
  - [預編譯包](#precompiled-packages)
    - [CentOS 包](#centos-packages)
    - [Ubuntu 包](#ubuntu-packages)
  - [源代碼](#source-code)
    - [獲得源代碼](#getting-sources)
      - [Mercurial 源](#mercurial-repository)
      - [GitHub 源](#github-repository)
      - [Tarball](#tarball)
    - [安裝需要的軟件](#installing-required-software)
      - [Ubuntu 依賴軟件](#ubuntu-prerequisits)
      - [CentOS 依賴軟件](#centos-prerequisits)
    - [配置源代碼](#configuring-sources)
      - [配置Go語言包](#configuring-go-package)
      - [建立壹個Go應用](#building-the-go-applications)
      - [配置PHP模塊](#configuring-php-modules)
      - [配置Python模塊](#configuring-python-modules)
    - [編譯源代碼](#compiling-sources)
    - [從源代碼安裝](#installing-from-sources)
- [配置](#configuration)
  - [應用](#applications)
  - [監聽器](#listeners)
  - [最小化配置](#minimum-configuration)
  - [建立配置對象](#creating-configuration-objects)
    - [示例：壹個完整的配置](#example-create-a-full-configuration)
    - [示例：創建壹個應用](#example-create-an-application-object)
  - [顯示配置的對象](#displaying-configuration-objects)
    - [示例：顯示完整的配置](#example-display-the-full-configuration)
    - [示例：顯示壹個對象](#example-display-one-object)
  - [自定義對象的配置](#modifying-configuration-objects)
    - [示例：為監聽器修改壹個應用](#example-change-the-application-for-a-listener)
    - [示例：修改應用的文件路徑](#example-change-the-file-path-for-an-application)
  - [刪除配置的對象](#deleting-configuration-objects)
    - [示例：刪除壹個監聽器](#example-delete-a-listener)
  - [監聽器和應用對象](#listener-and-application-objects)
    - [監聽器](#listener)
    - [Go語言應用](#go-application)
    - [PHP語言應用](#php-application)
    - [Python語言應用](#python-application)
    - [完整示例](#full-example)
- [和NGINX結合](#integration-with-nginx)
  - [在NGINX後安裝單元](#installing-unit-behind-nginx)
     - [示例 1](#installing-unit-example1)
     - [示例 2](#installing-unit-example2)
  - [安全和代理單元的API](#securing-and-proxying-unit-api)
- [貢獻](#contribution)
- [疑難解答](#troubleshooting)

<!-- /menu -->

<!-- section:1 -->

## NGINX Unit

NGINX Unit 是壹個動態的網絡應用服務器，它的設計初衷就是可運行多種編程語言的。通過API可以輕巧，多面化的動態配置Unit。當工程師或操作者有需要時，可以輕松重構服務器已適配特殊的應用參數。

NGINX Unit 現在是beta版本。妳現在雖然可以使用它，但建議僅用於測試環境，不建議用於生產環境。

本項目的源代碼及分發均使用Apache 2.0 license。

### 核心功能

   * 使用RESTful JSON API可完整的動態重配置服務器。
   * 可同時運行多語言及多版本的應用。
   * 動態語言的進程管理功能。 (敬請期待)
   * TLS 支持 (敬請期待)
   * TCP, HTTP, HTTPS, HTTP/2 路由和代理 (敬請期待)

### Supported Application Languages

   * Python
   * PHP
   * Go
   * JavaScript/Node.js (敬請期待)
   * Java (敬請期待)
   * Ruby (敬請期待)

<!-- /section:1 -->

<!-- section:2 -->

## 安裝

### 系統需求

NGINX Unit 已被測試通過在以下系統上運行:
   * Linux 2.6 或更高
   * FreeBSD 9 或更高
   * MacOS X
   * Solaris 11

系統架構:
   * i386
   * amd64
   * powerpc
   * arm

NGINX Unit 支持不同的編程語言，妳可以選擇下面列出的版本:
   * Python 2.6, 2.7, 3
   * PHP 5, 7
   * Go 1.6 or later

妳可以在壹個系統上運行不同版本的相同編程語言。

### 安裝包

妳可以在CentOS&nbsp;7.0 和 Ubuntu&nbsp;16.04&nbsp;LTS。上直接安裝 NGINX Next

#### CentOS 安裝

   1. 在 **/etc/yum.repos.d/unit.repo** 目錄下建立文件，並包含以下內容:

   ```
   [unit]
   name=unit repo
   baseurl=http://nginx.org/packages/mainline/centos/7/$basearch/
   gpgcheck=0
   enabled=1
   ```

   2. 安裝Nginx Unit:

   ```
   # yum install unit
   ```

#### Ubuntu 安裝

   1. 下載key [key](http://nginx.org/keys/nginx_signing.key) 用於簽名NGINX,&nbsp;Inc. 的源和包。

   2. 添加秘鑰到 `apt` 程序裏。程序將會認證NGINX源的簽名，這樣將會消除警告。

   ```
   # sudo apt-key add nginx_signing.key
   ```

   3. 將下面兩行寫入文件尾部。
   **/etc/apt/sources.list**:

   ```
   deb http://nginx.org/packages/mainline/ubuntu/ xenial nginx
   deb-src http://nginx.org/packages/mainline/ubuntu/ xenial nginx
   ```

   4. 安裝NGINX Unit:

   ```
   # apt-get update
   # apt-get install unit
   ```

### 源代碼

本章將會完整的解釋如何通過源代碼安裝NIGIX Unit。

#### 獲得源代碼

妳可以通過三種方法獲得NGINX Unit的源代碼: 從 NGINX,&nbsp;Inc.
的Mercurial源，Github，或從tarball獲得源代碼。

無論從那種方式獲得源代碼，妳均可以在 **unit** 子目錄中，找到我們的源代碼。

##### Mercurial源

   1. 如果妳沒有安裝Mercurial軟件。妳需要先下載並安裝它。
   示例：在 Ubuntu 系統下，運行下面的命令:

   ```
   # apt-get install mercurial
   ```

   2. 下載NIGIX Unit的源代碼:

   ```
   # hg clone http://hg.nginx.org/unit
   ```

##### GitHub 源

   1. 如果妳沒有Git，請先移步Github幫助妳安裝Git
   [GitHub 幫助文檔](https://help.github.com/)。

   2. 下載NGINX Unit源:

   ```
   # git clone https://github.com/nginx/unit
   ```

##### Tarball

NGINX Unit源代碼請在以下鏈接獲得
[http://unit.nginx.org/download/](http://unit.nginx.org/download/)

#### 安裝依賴軟件

在配置和安裝 NGINX Unit 之前，妳必須現安裝依賴文件和必要的工具。以及妳希望運行的編程語言。如 Go，PHP，和 Python。
##### Ubuntu 依賴安裝

   1. 安裝 build tools。

   ```
   # apt-get install build-essential
   ```

   2. 如果想支持Go語言應用，請安裝 `golang` 包。

   ```
   # apt-get install golang
   ```

   3. 如果想支持PHP語言應用，請安裝 `php-dev` 和 `libphp-embed` 包。

   ```
   # apt-get install php-dev
   # apt-get install libphp-embed
   ```

   4. 如果想支持Python語言應用，請安裝 `python-dev` 包。

   ```
   # apt-get install python-dev
   ```

##### CentOS 依賴

   1. 安裝 build tools。

   ```
   # yum install gcc make
   ```

   2. 如果想支持Go語言應用，請安裝 `golang` 包。

   ```
   # yum install golang
   ```

   3. 如果想支持PHP語言應用，請安裝 `php-devel` 和 `libphp-embedded` 包。

   ```
   # yum install php-devel php-embedded
   ```

   4. 如果想支持Python語言應用，請安裝 `python-devel` 包。

   ```
   # yum install python-devel
   ```

#### 配置源代碼

使用NGINX Unit，妳可以同時運行不同版本的編程語言。（Go，PHP，或者Python）。妳需要配置壹個separate（分區）。
NGINX Unit有不同的模塊。下面的命令會給不同的模塊創建分區。 **Makefile**

##### 配置Go語言環境

NGINX Unit 會提供Go的依賴包，供妳方便配置NGINX Unit內的Go使用環境。

   1. 使用下面的設置 `GOPATH` 的環境變量。

   ```
   # export GOPATH=/home/user/go_apps
   ```

   2. 運行以下命令:

   ```
   # ./configure go
   configuring Go package
   checking for Go ... found
    + go version go1.6.2 linux/amd64
    + Go package path: "/home/user/go_apps"
   ```

##### 建立Go應用

   1. 定義Go的源文件，以適應NGINX Unit。

       a. 在 `import` 區域，在尾行添加 `"unit"` 。

      ```
      import {
          "fmt"
          "net/http"
          "unit"
      }
      ```

       b. 在 `main()` 功能中， 註釋 `http.ListenandServe`
       功能並添加 `unit.ListenAndServe` 功能。

      ```
      func main() {
           http.HandleFunc("/", handler)
           //http.ListenAndServe(":8080", nil)
           unit.ListenAndServe(":8080", nil)
      ```

   2. 建立 GO應用。

      ```
      # go build
      ```

如果妳直接運行Go應用，Go將會自動使用http.ListenandServe。如果使用NGINX Unit，啟動Go程序，將會自動執行unit.ListenandServe。程序將會與Unit的路由進行交互。

##### 配置PHP模塊

配置PHP模塊。( **php.unit.so**) 運行下面的命令進行自動配置PHP:

```
# ./configure php
```

如需要配置不同版本的PHP，請使用下面的命令:

```
# ./configure php --module=<prefix> --config=<script-name> --lib-path=<pathname>
```

當

   * `--module` 設置文件名的前綴。Unit被設置為特定的版本。( &lt;prefix&gt;.**unit.so**)。

   * `--config` 欽定的文件名， **php-config** 特定版本的PHP。

   * `--lib-path` PHP的路徑。

實例：下面這個命令將會生成壹個模塊 **php70.unit.so** 已適配PHP7.0
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

##### 配置Python模塊

配置特定的Python模塊，已適配NGINX Unit。 (叫 **python.unit.so**) 。
在操作系統的根目錄可以找到configure，使用下面的命令。

```
# ./configure python
```

如果需要配置其他的Python版本，請使用下面的命令。

```
# ./configure python --module=<prefix> --config=<script-name>
```

當

   * `--module` 會生成壹個模塊，設置文件名的前綴。Unit被設置為特定的版本， (就這麽簡單，將會生成壹個
   &lt;prefix&gt;.**unit.so**).

   * `--config` 欽定的文件名 **python-config** 將會生成特定版本的模塊。

示例：下面的命令將會生成壹個名為 **py33.unit.so** 已適配
Python&nbsp;3.3:

```
# ./configure php --module=py33  \
                  --config=python-config-3.3
configuring Python module
checking for Python ... found
checking for Python version ... 3.3
 + Python module: py33.unit.so
```

#### 完成編譯

當完成NGINX Unit的PHP, Python模塊編譯後, 運行下面的命令:

```
# make all
```

編譯適用於Go語言的NGINX Unit:

   1. 確認`GOPATH` 環境變量已被正確設置。

   ```
   # go env GOPATH

   # export GOPATH=<path>
   ```

   2. 完成編譯:

   ```
   # make go-install
   ```

#### 從源代碼安裝

如果需要安裝完整的全面模塊和Go包，運行下面的命令:

```
# make install
```

<!-- /section:2 -->

<!-- section:3 -->

## 配置

默認情況下，Control Socket內包含的的API來控制NGINX Unit
**unit.control.sock**.

### 應用

每個單獨的應用，妳都可以在NGINX Unit的配置文件中，使用JSON語法來定義壹個
`applications`。使用JSON語法來定義裏面的內容，如使用的編程語言，需要的工作數，文件的本地路徑，以及其他參數。
這個示例配置了壹個PHP網站，名為 **blogs** 而這個網站的本地路徑為。 **/www/blogs/scripts**。默認頁面為 **index.php**。

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

### 監聽器

當應用被通過HTTP訪問時，妳必須定義至少壹個監聽器 `listeners`。監聽器是壹個IP地址和壹個被定義的端口，當用戶訪問時，Unit的監聽器會返回正確結果。IP地址可以是壹個完整的IP地址(示例，
`127.0.0.1:8300`)或(示例，`*:8300`).

在這個示例中，端口&nbsp;8300 的請求全部會被發送至 **blogs**
這個應用:

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


完整的JSON語法細節，請點擊下面的鏈接。
[JSON 詳細的監聽器配置和應用配置](#json-specification-for-listener-and-application-objects).

### 最小化配置

配置中至少需要包含壹個監聽器和壹個應用配置:

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

### 創建配置文件

妳可以創建壹個配置文件，並且發送壹個 `PUT` 請求。為了減少發生錯誤的可能，當使用 `curl` 命令式，請包含 `-d` 選項。

#### 示例：創建壹個完整的配置文件

通過下面的命令，可以創建壹個初始的配置文件
**start.json** :

```
# curl -X PUT -d @/path/to/start.json  \
       --unix-socket ./control.unit.sock http://localhost/
```

#### 示例：新建壹個應用對象

通過 **wiki.json** 我們可以創建壹個 **wiki** 應用。

```
# curl -X PUT -d @/path/to/wiki.json  \
       --unix-socket ./control.unit.sock http://localhost/applications/wiki
```

**wiki.json** 裏包含了：

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

### 顯示配置的對象

要顯示配置的對象，它被附加在`curl` 的URL內。

#### 示例：顯示完整的配置文件

如果妳想顯示完整的配置文件，妳可以通過下面的指令來查看：

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

#### 示例：顯示壹個對象

顯示 **wiki** 這個應用的配置，只需：

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

### 修改配置的對象：

要更改配置的對象，使用 `curl` 命令和`-d` 選項來實現特定的對象的JSON數據，然後發送壹個`PUT`請求。

#### 示例：修改監聽端口指向的應用

在端口 *:8400上修改 `application` 應用指向 **wiki-dev**：

```
# curl -X PUT -d '"wiki-dev"' --unix-socket ./control.unit.sock  \
       'http://localhost/listeners/*:8400/application'
{
    "success": "Reconfiguration done."
}
```

#### 示例：修改應用的本地路徑

修改`root`對象的 **blogs** 應用的本地路徑至
**/www/blogs-dev/scripts**:

```
# curl -X PUT -d '"/www/blogs-dev/scripts"'  \
       --unix-socket ./control.unit.sock  \
       http://localhost/applications/blogs/root
{
    "success": "Reconfiguration done."
}
```

### 刪除對象

要刪除配置的對象，妳可以通過 `curl` 發送壹個`DELETE` 請求到對象目錄。

#### 示例：刪除監聽器

刪除對 *:8400 端口的監聽：

```
# curl -X DELETE --unix-socket ./control.unit.sock  \
       'http://localhost/listeners/*:8400'
{
    "success": "Reconfiguration done."
}
```

### 監聽器和應用對象

#### 監聽器

|  對象 | 描述 |
| --- | --- |
| `<IP地址>:<端口>`          | IP地址和端口需在不同的Unit監聽器上均需要配置應用的名字 ，IP地址可以是完整的 (`127.0.0.1:8300`) 或者(`*:8300`).
| `application` | 應用名。

示例：

```
"*:8300": {
           "application": "blogs"
          }
```

#### Go語言應用

|  對象 | 描述 |
| --- | --- |
| `type`| 應用的編程語言 (`go`)。
| `workers`           | 應用的工作數量。
| `executable`        | 完整的本地路徑。
| `user` (optional)   | 運行進程的用戶，如未定義，則默認（nobody）。
| `group` (optional)  | 用戶所在的用戶組 。如未定義，則默認。

示例:

```
"go_chat_app": {
            "type": "go",
            "executable": "/www/chat/bin/chat_app",
            "user": "www-go",
            "group": "www-go"
        }
```

#### PHP語言應用

|  對象 | 描述 |
| --- | --- |
| `type`| 應用的編程語言 (`php`).
| `workers`           | 應用的工作數量。
| `root`              | 文件的本地路徑。
| `index`             | 默認的index文件路徑。
| `script` (optional) | 訪問Unit內任意的URL均會運行，填寫路徑將不要填寫物理路徑，請填寫虛擬路徑。
| `user` (optional)   | 運行進程的用戶，如未定義，則默認（nobody）。
| `group` (optional)  | 用戶所在的用戶組 。如未定義，則默認。

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

#### Python語言應用

|  Object | Description |
| --- | --- |
| `type`| 應用的編程語言 (`python`)。
| `workers`           | 應用的工作數量。
| `path`             | **wsgi.py** 的路徑。
| `module`             | 必填。目前只支持 `wsgi`。
| `user` (optional)   | 運行進程的用戶，如未定義，則默認（nobody）。
| `group` (optional)  | 用戶所在的用戶組 。如未定義，則默認。

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

## NGINX壹起使用

### 和NGINX壹起使用

配置NGINX來進行靜態文件的處理和接受代理的請求。
NGINX服務器將直接處理靜態文件的訪問請求，動態文件的處理將會直接轉發到NGINX Unit。
新建壹個上傳模塊，在NGINX的配置中，將http的請求轉發給Unit，示例：
```
upstream unit_backend {
    server 127.0.0.1:8300;
}
```

新建或修改NGINX的配置文件 `server`塊和 `location`塊 。指定的靜態文件的路徑和上傳模塊。
#### 示例 1

這個例子適用於基於PHP編程語言開發的程序。，全部的URL請求，如已.php結尾，均會被轉發至Unit服務器，其他的全部文件將會直接被服務器返回文件：

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
下面的應用，全部都靜態文件需要被放置在`/var/www/files` 目錄下，在前端調用時，請直接使用`/static`。
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


相關的NGINX 文檔將會在[http://nginx.org](http://nginx.org)提供。
相關的支持和更多的功能將在[https://www.nginx.com](https://www.nginx.com)上提供。

### 安全和代理Unit API

默認情況下，Unit的API將會在Unix domain socket下。如果妳希望API可以被遠程訪問，妳需要使用NGINX配置代理。
NGINX 可以提供安全的、可信的和可控制的API
使用下面的示例配置來配置NGINX：

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

## 貢獻

NGINX Unit的發布和分發均使用Apache 2.0 license。
如果想貢獻自己的力量，妳可以選擇通過郵件[unit@nginx.org](mailto:unit@nginx.org)
或者在Github上提交PR[https://github.com/nginx/unit](https://github.com/nginx/unit)。
如果在中文翻譯方面需要改近請聯系[@tuzimoe](https://github.com/tuzimoe)。
<!-- /section:5 -->

<!-- section:6 -->

## 疑難解答

Unit 日誌壹般在默認的位置，可以在`/var/log/unit.log` 中找到。
Log 文件的位置也可以通過運行 `unitd --help` 來快速定位。
詳細的Debug日誌可以通過輸入命令來獲得：
```
./configure --debug
```

輸入完命令後，請務必重新編譯和重裝NGINX Unit。
請註意，debug日誌的內容將會以快速的增長。

社區郵箱的列表將會在<unit@nginx.org>上找到。
訂閱郵箱列表，可以通過發送任何內容至訂閱
[unit-subscribe@nginx.org](mailto:unit-subscribe@nginx.org)
或直接點擊此處訂閱
[沒錯就是我](http://mailman.nginx.org/mailman/listinfo/unit)。



<!-- /section:6 -->
