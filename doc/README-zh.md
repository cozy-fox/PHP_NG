ngx_php
======
[![Build Status](https://travis-ci.org/rryqszq4/ngx_php.svg?branch=master)](https://travis-ci.org/rryqszq4/ngx_php) 
[![Gitter](https://badges.gitter.im/rryqszq4/ngx_php.svg)](https://gitter.im/rryqszq4/ngx_php?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)
[![GitHub release](https://img.shields.io/github/release/rryqszq4/ngx_php.svg)](https://github.com/rryqszq4/ngx_php/releases/latest)
[![license](https://img.shields.io/badge/license-BSD--2--Clause-blue.svg)](https://github.com/rryqszq4/ngx_php/blob/master/LICENSE)

[ngx_php](https://github.com/rryqszq4/ngx_php)是嵌入php脚本的nginx模块。你也可以称它为nginx-php5-module。  
[English document](https://github.com/rryqszq4/ngx_php/blob/master/doc/README-en.md) | [中文文档](https://github.com/rryqszq4/ngx_php/blob/master/doc/README-zh.md)  
QQ 群：558795330

特性
--------
* 支持加载php.ini配置文件  
可以在nginx的配置文件中加载php的配置文件
* 支持原生php的全局变量$_GET, $_POST, $_COOKIE, $_SERVER, $_FILES, $_SESSION...
* 支持运行php代码与文件  
可以在nginx的配置文件中书写代码，也可以在配置文件中加载代码
* 支持RFC 1867文件上传协议
* 支持php错误输出
* 支持加载与运行PECL扩展  
遗憾的是部分扩展是阻塞方式的，可以正常运行但在ngx_php中并不能换来性能的提升
* 支持nginx的API在php中调用  
利用php扩展封装了一些nginx的底层接口，方便在php中调用

环境
-----------
- PHP 5.3.* ~ PHP 5.6.*
- nginx-1.7.12 ~ nginx-1.11.8

安装
-------
**安装php**  
需要编译php，并且需要开启线程安全和编译动态共享库
```sh
$ wget http://php.net/distributions/php-5.3.29.tar.gz
$ tar xf php-5.3.29.tar.gz
$ cd php-5.3.29

$ ./configure --prefix=/path/to/php \
$             --enable-maintainer-zts \
$             --enable-embed
$ make && make install
```

**安装ngx_php**  
编译完php就可以开始安装ngx_php，需要重新编译nginx并加入ngx_php模块
```sh
$ git clone https://github.com/rryqszq4/ngx_php.git

$ wget 'http://nginx.org/download/nginx-1.7.12.tar.gz'
$ tar xf nginx-1.7.12.tar.gz
$ cd nginx-1.7.12

$ export PHP_BIN=/path/to/php/bin
$ export PHP_INC=/path/to/php/include/php
$ export PHP_LIB=/path/to/php/lib

$ ./configure --user=www --group=www \
$             --prefix=/path/to/nginx \
$             --with-ld-opt="-Wl,-rpath,$PHP_LIB" \
$             --add-module=/path/to/ngx_php/dev/ngx_devel_kit \
$             --add-module=/path/to/ngx_php
$ make && make install
```

摘要
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

典型框架配置
--------------

**yaf & yii (单一入口模式):**

```nginx
server {
    listen 80;
    server_name yaf-sample.com;
    access_log  logs/yaf-sample.com.access.log;

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

**wordpress (多入口模式):**

```nginx
server {
    listen 80;
    server_name wordpress-sample.com;
    
    location ~ \.php$ {
        root   /home/www/wordpress;
        content_by_php "
            require_once('/home/www/wordpress'.$_SERVER['DOCUMENT_URI']);
        ";
    }
}
```

测试
----
使用perl语言开发的[Test::Nginx](https://github.com/openresty/test-nginx)的测试模块进行测试, 用来发现ngx_php在开发与使用中存在的问题与缺陷。 

```sh
cd /path/to/ngx_php
export PATH=/path/to/nginx/sbin:$PATH
prove -r t
```

测试结果:

```sh
t/001-hello.t ........... ok
t/002-ini.t ............. ok
t/003-_GET.t ............ ok
t/004-_POST.t ........... ok
t/005-_SERVER.t ......... ok
t/006-_COOKIE.t ......... ok
t/007-_FILES.t .......... ok
t/008-error.t ........... ok
t/009-session.t ......... ok
t/100-ngx_socket_tcp.t .. ok
t/200-rewrite_by_php.t .. ok
t/202-access_by_php.t ... ok
All tests successful.
Files=12, Tests=40,  4 wallclock secs ( 0.06 usr  0.01 sys +  1.23 cusr  0.46 csys =  1.76 CPU)
Result: PASS
```

nginx指令
----------
* [php_ini_path](#php_ini_path)
* [init_by_php](#init_by_php)
* [init_by_php_file](#init_by_php_file)
* [rewrite_by_php](#rewrite_by_php)
* [rewrite_by_php_file](#rewrite_by_php_file)
* [access_by_php](#access_by_php)
* [access_by_php_file](#access_by_php_file)
* [content_by_php](#content_by_php)
* [content_by_php_file](#content_by_php_file)
* [log_by_php](#log_by_php)
* [log_by_php_file](#log_by_php_file)
* [content_thread_by_php](#content_thread_by_php)
* [content_thread_by_php_file](#content_thread_by_php_file)
* [set_by_php](#set_by_php)
* [set_run_by_php](#set_run_by_php)
* [set_by_php_file](#set_by_php_file)
* [set_run_by_php_file](#set_run_by_php_file)

php_ini_path
------------
**语法:** *php_ini_path &lt;php.ini file path&gt;*  

**环境:** *http*  

**阶段:** *loading-config*  

加载php配置文件

```nginx
php_ini_path /usr/local/php/etc/php.ini;
```

init_by_php
-----------
**语法:** *init_by_php &lt;php script code&gt;*  

**环境:** *http*  

**阶段:** *loading-config*

init_by_php_file
----------------
**语法:** *init_by_php_file &lt;php script file&gt;*  

**环境:** *http*  

**阶段:** *loading-config*

rewrite_by_php
--------------
**语法:** *rewrite_by_php &lt;php script code&gt;*  

**环境:** *http, server, location, location if*  

**阶段:** *rewrite*  

nginx的rewrite阶段运行php代码。

rewrite_by_php_file
-------------------
**语法:** *rewrite_by_php_file &lt;php script file&gt;*  

**环境:** *http, server, location, location if*  

**阶段:** *rewrite*

access_by_php
-------------
**语法:** *access_by_php &lt;php script code&gt;*  

**环境:** *http, server, location, location if*  

**阶段:** *access*  

nginx的access阶段运行php代码。

access_by_php_file
------------------
**语法:** *access_by_php_file &lt;php script file&gt;*  

**环境:** *http, server, location, location if*  

**阶段:** *access*

content_by_php
--------------
**语法:** *content_by_php &lt;php script code&gt;*  

**环境:** *http, server, location, location if*  

**阶段:** *content*  

ngx_php核心处理阶段，可以执行php代码，但是这个指令被设计为以阻塞方式运行php代码，因此不要使用此指令做io操作。
```nginx
location /content_by_php {    
    content_by_php "
        header('Content-Type: text/html;charset=UTF-8');
    
        echo phpinfo();
    ";
        
}
```

content_by_php_file
-------------------
**语法:** *content_by_php_file &lt;php script file&gt;*  

**环境:** *http, server, location, location if*  

**阶段:** *content*  

ngx_php核心处理阶段，可以执行php文件，但是这个指令被设计为以阻塞方式执行php文件，因此不要使用此指令做io操作。
```nginx
location /content_by_php_file {
        content_by_php_file /home/www/index.php;
}
```

log_by_php
----------
**语法:** *log_by_php &lt;php script code&gt;*  

**环境:** *http, server, location, location if*  

**阶段:** *log*  

nginx的log阶段运行php代码。

log_by_php_file
---------------
**语法:** *log_by_php_file &lt;php script file&gt;*  

**环境:** *http, server, location, location if*  

**阶段:** *log*

content_thread_by_php
---------------------
**语法:** *content_thread_by_php &lt;php script code&gt;*  

**环境:** *http, server, location, location if*  

**阶段:** *content*  

ngx_php核心处理阶段，可以执行php代码，底层使用nginx异步机制＋多线程实现以非阻塞方式运行php代码。
```nginx
location /content_thread_by_php {
    content_thread_by_php "
        echo 'hello world';

        $res = ngx_location::capture('/list=s_sh000001');
        var_dump($res);
        
        $capture_multi = array(
                            '/list=s_sh000001',
                            '/list=s_sh000001',
                            '/list=s_sh000001'
                    );
        $res = ngx_location::capture_multi($capture_multi);
        var_dump($res);
        
        $res = ngx_location::capture('/list=s_sh000001');
        var_dump($res);
        
        $res = ngx_location::capture('/list=s_sh000001');
        #var_dump($res);
    ";
}

location /list {
    proxy_pass http://hq.sinajs.cn;
    proxy_set_header Accept-Encoding "";
}
```

content_thread_by_php_file
--------------------------
**语法:** *content_thread_by_php_file &lt;php script file&gt;*  

**环境:** *http, server, location, location if*  

**阶段:** *content*  

ngx_php核心处理阶段，可以执行php文件，底层使用nginx异步机制＋多线程实现以非阻塞方式运行php文件。

set_by_php
----------
**语法:** *set_by_php &lt;php script code&gt;*  

**环境:** *server, server if, location, location if*  

**阶段:** *content*

set_run_by_php
--------------
**语法:** *set_run_by_php &lt;php script code&gt;*  

**环境:** *server, server if, location, location if*  

**阶段:** *content*

set_by_php_file
---------------
**语法:** *set_by_php_file &lt;php script file&gt;*  

**环境:** *server, server if, location, location if*  

**阶段:** *content*

set_run_by_php_file
-------------------
**语法:** *set_run_by_php_file &lt;php script file&gt;*  

**环境:** *server, server if, location, location if*  

**阶段:** *content*


Nginx的php接口
-------------
* [ngx::_exit](#ngx_exit)
* [ngx_location::capture](#ngx_locationcapture)
* [ngx_location::capture_multi](#ngx_locationcapture_multi)
* [ngx_socket_tcp::__construct](#ngx_socket_tcp__construct)
* [ngx_socket_tcp::connect](#ngx_socket_tcpconnect)
* [ngx_socket_tcp::send](#ngx_socket_tcpsend)
* [ngx_socket_tcp::receive](#ngx_socket_tcpreceive)
* [ngx_socket_tcp::close](#ngx_socket_tcpclose)
* [ngx_socket_tcp::settimeout](#ngx_socket_tcpsettimeout)
* [ngx_log::error](#ngx_logerror)
* [ngx_time::sleep](#ngx_timesleep)

ngx::_exit
----------
**语法:** *ngx::_exit(int $status)*  

**环境:** *content_by_php* *content_thread_by_php*  

```php
echo "start\n";
ngx::_exit(200);
echo "end\n";
```

ngx_location::capture
---------------------
**语法:** *ngx_location::capture(string $uri)*  

**环境:** *content_thread_by_php*  

借助nginx底层强大的subrequest，实现php完全非阻塞调用

```php
$result = ngx_location::capture('/foo');
echo $result;
```

ngx_location::capture_multi
---------------------------
**语法:** *ngx_location::capture_multi(array $uri)*  

**环境:** *content_thread_by_php*  

和ngx_location::capture相似，但是可以支持完全非阻塞的并行调用

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
**语法:** *ngx_socket_tcp::__construct()*  

**环境:** *content_thread_by_php*  

```php
$tcpsock = new ngx_socket_tcp();
```

ngx_socket_tcp::connect
---------------------------
**语法:** *ngx_socket_tcp::connect(string $host, int $port)*  

**环境:** *content_thread_by_php*  

resolver 8.8.8.8;

```php
$tcpsock = new ngx_socket_tcp();
$tcpsock->connect('127.0.0.1',11211));
```

ngx_socket_tcp::send
---------------------------
**语法:** *ngx_socket_tcp::send(string $buf)*  

**环境:** *content_thread_by_php*  

```php
$tcpsock = new ngx_socket_tcp();
$tcpsock->connect('127.0.0.1',11211));
$tcpsock->send('stats\r\n');
```

ngx_socket_tcp::receive
---------------------------
**语法:** *ngx_socket_tcp::receive()*  

**环境:** *content_thread_by_php*  

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
**语法:** *ngx_socket_tcp::close()*  

**环境:** *content_thread_by_php*  

ngx_socket_tcp::settimeout
---------------------------
**语法:** *ngx_socket_tcp::settimeout(int time)*  

**环境:** *content_thread_by_php*  

ngx_log::error
--------------
**语法:** *ngx_log::error(int level, string log)* 

**环境:** *content_thread_by_php*  

Nginx的错误日志等级，在php中的实现。
* NGX_LOG_STDERR
* NGX_LOG_EMERG
* NGX_LOG_ALERT
* NGX_LOG_CRIT
* NGX_LOG_ERR
* NGX_LOG_WARN
* NGX_LOG_NOTICE
* NGX_LOG_INFO
* NGX_LOG_DEBUG

```php
ngx_log::error(NGX_LOG_ERR, "test");

/*
 2016/10/06 22:10:19 [error] 51402#0: *1 test while reading response header from upstream, client: 192.168.80.1, 
 server: localhost, request: "GET /_mysql HTTP/1.1", upstream: "127.0.0.1:3306", host: "192.168.80.140"
*/
```

ngx_time::sleep
---------------
**语法:** *ngx_time::sleep(int seconds)* 

**环境:** *content_thread_by_php*  

由于php的标准sleep函数会阻塞nginx，所以基于nginx底层的定时器实现了ngx_time::sleep，可以在nginx中实现非阻塞sleep

```php
echo "sleep_start\n";

ngx_time::sleep(3);

echo "sleep_end\n"; 
```

问题
--------
[issues #6](https://github.com/rryqszq4/ngx_php/issues/6) - 注意在 php-5.3.29 中, libxml2 2.7.6 不是线程安全的. 可以尝试在安装php阶段，禁用xml.
```sh
./configure --prefix=/usr/local/php5329 \
            --with-config-file-path=/usr/local/php5329/etc \
            --with-iconv=/usr/local/libiconv \
            --disable-xml \
            --disable-libxml \
            --disable-dom \
            --disable-simplexml \
            --disable-xmlreader \
            --disable-xmlwriter \
            --without-pear \
            --enable-maintainer-zts  \
            --enable-embed
```

拷贝与授权
---------------------
Copyright (c) 2016-2017, rryqszq4 <ngxphp@gmail.com>
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
