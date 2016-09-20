ngx_php
======
[![Build Status](https://travis-ci.org/rryqszq4/ngx_php.svg?branch=master)](https://travis-ci.org/rryqszq4/ngx_php) 
[![Gitter](https://badges.gitter.im/rryqszq4/ngx_php.svg)](https://gitter.im/rryqszq4/ngx_php?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)
[![image](https://img.shields.io/badge/license-BSD-blue.svg)](https://github.com/rryqszq4/ngx_php/blob/master/LICENSE)

[ngx_php](https://github.com/rryqszq4/ngx_php) - Embedded php script language for nginx-module. Another name is php-nginx-module.   
QQ group：558795330

Features
--------
* Load php.ini config file
* Global variable support $_GET, $_POST, $_COOKIE, $_SERVER, $_FILES, $_SESSION...
* PHP script code and file execute
* RFC 1867 protocol file upload
* PHP error reporting output
* Support PECL PHP extension
* Support Nginx API for php

Requirement
-----------
- PHP 5.3.*  
PHP 5.4.*  
PHP 5.5.*  
PHP 5.6.*
- nginx-1.4.7  
nginx-1.6.3  
nginx-1.8.1  
nginx-1.9.15

Installation
-------
- **build php**

```sh
wget 'http://php.net/distributions/php-5.3.29.tar.gz'
tar xf php-5.3.29.tar.gz
cd php-5.3.29

./configure --prefix=/path/to/php \
            --enable-maintainer-zts \
            --enable-embed
make && make install
```

- **build ngx_php**

```sh
git clone https://github.com/rryqszq4/ngx_php.git

wget 'http://nginx.org/download/nginx-1.6.3.tar.gz'
tar xf nginx-1.6.3.tar.gz
cd nginx-1.6.3

export PHP_BIN=/path/to/php/bin
export PHP_INC=/path/to/php/include/php
export PHP_LIB=/path/to/php/lib

./configure --user=www --group=www \
			--prefix=/path/to/nginx \
			--with-ld-opt="-Wl,-rpath,$PHP_LIB" \
			--add-module=/path/to/ngx_php/dev/ngx_devel_kit \
			--add-module=/path/to/ngx_php
make && make install
```

Synopsis
--------

```nginx
user www www;
worker_processes  4;

events {
    worker_connections  1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    keepalive_timeout  65;
	
    client_max_body_size 10m;   
    client_body_buffer_size 4096k;

    php_ini_path /usr/local/php/etc/php.ini;

	server {
        listen       80;
        server_name  localhost;
	
		location /php {
			content_by_php '
				echo "hello ngx_php";
			';
		}
	}
}
```

Framework conf
--------------

**wordpress :**

```nginx
server {
	listen 80;
	server_name	wordpress-sample.com;
	
	location ~ \.php$ {
        root   /home/www/wordpress;
        content_by_php "
            require_once('/home/www/wordpress'.$_SERVER['DOCUMENT_URI']);
        ";
    }
}
```

**yaf & yii :**

```nginx
server {
    listen 80;
	server_name	yaf-sample.com;
	access_log	logs/yaf-sample.com.access.log;

	root /home/www/yaf-sample;
	index index.php index.html;
	
	location /favicon.ico {
		log_not_found off;
	}

	location / {
		try_files $uri $uri/ /index.php$is_args$args;
	}

	location ~ \.php$ {
		content_by_php '
			header("Content-Type: text/html;charset=UTF-8");
			require_once("/home/www/yaf-sample/index.php");
		';
	}
}  
```

Test
----
Using the perl of [Test::Nginx](https://github.com/openresty/test-nginx) module to testing, searching and finding out problem in ngx_php. 

```sh
cd /path/to/ngx_php
export PATH=/path/to/nginx/sbin:$PATH
prove -r t
```
Test result:

```sh
t/001-hello.t .... ok   
t/002-ini.t ...... ok   
t/003-_GET.t ..... ok   
t/004-_POST.t .... ok   
t/005-_SERVER.t .. ok   
t/006-_COOKIE.t .. ok   
t/007-_FILES.t ... ok   
t/008-error.t .... ok
t/009-session.t .. ok     
All tests successful.
Files=9, Tests=20,  2 wallclock secs ( 0.03 usr  0.03 sys +  1.20 cusr  0.31 csys =  1.57 CPU)
Result: PASS
```

Directives
----------

php_ini_path
------------
**syntax:** *php_ini_path &lt;php.ini file path&gt;*  
**context:** *http*  
**phase:** *loading-config*  

* Loading php configuration file in nginx configuration initialization.

```nginx
php_ini_path /usr/local/php/etc/php.ini;
```

init_by_php
-----------
**syntax:** *init_by_php &lt;php script code&gt;*  
**context:** *http*  
**phase:** *loading-config*

* In nginx configuration initialization or boot time, run some php scripts.

init_by_php_file
----------------
**syntax:** *init_by_php_file &lt;php script file&gt;*  
**context:** *http*  
**phase:** *loading-config*

* In nginx configuration initialization or boot time, run some php script file.

rewrite_by_php
--------------
**syntax:** *rewrite_by_php &lt;php script code&gt;*  
**context:** *http, server, location, location if*  
**phase:** *rewrite*

* Use php script redirect in nginx rewrite stage of.

```nginx
location /rewrite_by_php {
        rewrite_by_php "
            echo "rewrite_by_php";
            header('Location: http://www.baidu.com/');
        ";
    }
```

rewrite_by_php_file
-------------------
**syntax:** *rewrite_by_php_file &lt;php script file&gt;*  
**context:** *http, server, location, location if*  
**phase:** *rewrite*

* Use php script file, redirect in nginx rewrite stage of.

access_by_php
-------------
**syntax:** *access_by_php &lt;php script code&gt;*  
**context:** *http, server, location, location if*  
**phase:** *access*

* Nginx in the access phase, the php script determine access.

access_by_php_file
------------------
**syntax:** *access_by_php_file &lt;php script file&gt;*  
**context:** *http, server, location, location if*  
**phase:** *access*

* Nginx in the access phase, the php script file Analyzing access。

content_by_php
--------------
**syntax:** *content_by_php &lt;php script code&gt;*  
**context:** *http, server, location, location if*  
**phase:** *content*

* Most central command, run php script nginx stage of content.

content_by_php_file
-------------------
**syntax:** *content_by_php_file &lt;php script file&gt;*  
**context:** *http, server, location, location if*  
**phase:** *content*

* Most central command, run php script file nginx stage of content.

content_async_by_php
--------------------
**syntax:** *content_async_by_php &lt;php script code&gt;*  
**context:** *http, server, location, location if*  
**phase:** *content*  

* Asynchronous mode code to execute php code to call non-blocking.

content_sync_by_php
-------------------
**syntax:** *content_sync_by_php &lt;php script code&gt;*  
**context:** *http, server, location, location if*  
**phase:** *content*  

* Very similar content by php, but way synchronization code to execute php code 
  to call non-blocking, the development is only a test of each instruction.

set_by_php
----------
**syntax:** *set_by_php &lt;php script code&gt;*  
**context:** *server, server if, location, location if*  
**phase:** *content*

set_run_by_php
--------------
**syntax:** *set_run_by_php &lt;php script code&gt;*  
**context:** *server, server if, location, location if*  
**phase:** *content*

set_by_php_file
---------------
**syntax:** *set_by_php_file &lt;php script file&gt;*  
**context:** *server, server if, location, location if*  
**phase:** *content*

set_run_by_php_file
-------------------
**syntax:** *set_run_by_php_file &lt;php script file&gt;*  
**context:** *server, server if, location, location if*  
**phase:** *content*


Nginx API for php
-----------------
* ngx_location::capture_async
* ngx_location::capture_multi_async
* ngx_location::capture
* ngx_location::capture_multi
* ngx_socket_tcp::__construct
* ngx_socket_tcp::connect
* ngx_socket_tcp::send
* ngx_socket_tcp::receive
* ngx_socket_tcp::close

ngx_location::capture_async
---------------------------
**syntax:** *ngx_location::capture_async(string $uri, mixed $closure)*  
**context:** *content_async_by_php*  

* With nginx underlying strong subrequest, fully non-blocking asynchronous realize 
  php code calls.

```php
ngx_location::capture_async('/foo', function($callback = 'callback'){
    echo $callback;
});
```

ngx_location::capture_multi_async
---------------------------------
**syntax:** *ngx_location::capture_multi_async(array $uri, mixed $closure)*  
**context:** *content_async_by_php*  

* And ngx location :: capture async similar, but can support fully non-blocking asynchronous 
  parallel code calls.

```php
$capture_multi = array(
    '/foo',
    '/bar',
    '/baz'
);
ngx_location::capture_multi_async($capture_multi, function($callback = 'callback'){
    var_dump($callback);
});
```

ngx_location::capture
---------------------
**syntax:** *ngx_location::capture(string $uri)*  
**context:** *content_sync_by_php*  

* With nginx underlying strong subrequest, php achieve full non-blocking calls.

```php
$result = ngx_location::capture('/foo');
echo $result;
```

ngx_location::capture_multi
---------------------------
**syntax:** *ngx_location::capture_multi(array $uri)*  
**context:** *content_sync_by_php*  

* And ngx location :: capture similar, but can support full non-blocking concurrent calls.

```php
$capture_multi = array(
    '/foo',
    '/bar',
    '/baz'
);
$result = ngx_location::capture_multi($capture_multi);
var_dump($result);
```

ngx_socket_tcp::__construct
---------------------------
**syntax:** *ngx_socket_tcp::__construct()*  
**context:** *content_sync_by_php*  

```php
$tcpsock = new ngx_socket_tcp();
```

ngx_socket_tcp::connect
---------------------------
**syntax:** *ngx_socket_tcp::connect(string $host, int $port)*  
**context:** *content_sync_by_php*  

```php
$tcpsock = new ngx_socket_tcp();
$tcpsock->connect('127.0.0.1',11211));
```

ngx_socket_tcp::send
---------------------------
**syntax:** *ngx_socket_tcp::send(string $buf)*  
**context:** *content_sync_by_php*  

```php
$tcpsock = new ngx_socket_tcp();
$tcpsock->connect('127.0.0.1',11211));
$tcpsock->send('stats\r\n');
```

ngx_socket_tcp::receive
---------------------------
**syntax:** *ngx_socket_tcp::receive()*  
**context:** *content_sync_by_php*  

```php
$tcpsock = new ngx_socket_tcp();
$tcpsock->connect('127.0.0.1',11211));
$tcpsock->send('stats\r\n');
$result = $tcpsock->receive();
var_dump($result);
$tcpsock->close();
```

ngx_socket_tcp::close
---------------------------
**syntax:** *ngx_socket_tcp::close()*  
**context:** *content_sync_by_php*  

Question
--------
Issues #6
---------
Using in php-5.3.29, libxml2 2.7.6 not thread safety. Please disable xml in php install.
```sh
./configure --prefix=/usr/local/php5329 --with-config-file-path=/usr/local/php5329/etc --with-iconv=/usr/local/libiconv --disable-xml --disable-libxml --disable-dom --disable-simplexml --disable-xmlreader --disable-xmlwriter --without-pear --enable-maintainer-zts  --enable-embed
```

Copyright and License
---------------------
Copyright (c) 2016, rryqszq4 <ngxphp@gmail.com>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
