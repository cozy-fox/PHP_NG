# Version:0.0.1 by nginx 1.6  and php 5.6  ngx_php 0.0.3

#
# Dockerfile for ngx_php on centos  64bit
#

#
# Using Docker Image stuartjing/ngx_php
#
# Pulling
#   docker pull stuartjing/ngx_php
#
# Running
#  docker run -d -p 8080:80 stuartjing/ngx_php
#
# Access
#   curl http://127.0.0.1:8080/php
#

#
# Manual Build
#
# Building
#   docker build -t your_name:ngx_php .
#
# Runing
#   docker run -d -p 8080:80 your_name:ngx_php
#
# Access
#   curl http://127.0.0.1:8080/php
#



FROM docker.io/centos:latest
MAINTAINER jing "stuartjing@sina.com"

# init 
RUN mkdir /server
RUN cd /server && mkdir php nginx soft && cd soft
RUN yum install -y zip unzip wget make git gcc gcc-c++ autoconf libjpeg libjpeg-devel libpng libpng-devel freetype freetype-devel libpng libpng-devel libxml2 libxml2-devel zlib zlib-devel glibc glibc-devel glib2 glib2-devel bzip2 bzip2-devel ncurses curl openssl-devel gdbm-devel db4-devel libXpm-devel libX11-devel gd-devel gmp-devel readline-devel libxslt-devel expat-devel xmlrpc-c xmlrpc-c-devel

# libmcrypt
RUN set -x \
    && cd /usr/local/src/ \
    && wget "http://downloads.sourceforge.net/mcrypt/libmcrypt-2.5.8.tar.gz" \
    && tar -zxvf libmcrypt-2.5.8.tar.gz \
    && cd libmcrypt-2.5.8 \
    && ./configure \
    && make \
    && make install 

#php
RUN cd /server/soft/ 
RUN groupadd www && useradd -r -g www www
RUN set -x \ 
    && wget "http://cn2.php.net/distributions/php-5.6.0.tar.gz" \
    && tar zxvf php-5.6.0.tar.gz \
    && cd php-5.6.0 \
    && ./configure \
    --prefix=/server/php \
    --enable-fpm  \
    --with-ncurses  \
    --enable-soap  \
    --with-libxml-dir  \
    --with-XMLrpc  \
    --with-openssl  \
    --with-mcrypt  \
    --with-mhash  \
    --with-pcre-regex  \
    --with-sqlite3  \
    --with-zlib  \
    --enable-bcmath  \
    --with-iconv  \
    --with-bz2  \
    --enable-calendar  \
    --with-curl  \
    --with-cdb  \
    --enable-dom  \
    --enable-exif  \
    --enable-fileinfo  \
    --enable-filter  \
    --with-pcre-dir  \
    --enable-ftp  \
    --with-gd  \
    --with-openssl-dir  \
    --with-jpeg-dir  \
    --with-png-dir  \
    --with-zlib-dir  \
    --with-freetype-dir  \
    --enable-gd-native-ttf  \
    --enable-gd-jis-conv  \
    --with-gettext  \
    --with-gmp  \
    --with-mhash  \
    --enable-json  \
    --enable-mbstring  \
    --disable-mbregex  \
    --disable-mbregex-backtrack  \
    --with-libmbfl  \
    --with-onig  \
    --enable-pdo  \
    --with-pdo-mysql  \
    --with-zlib-dir  \
    --with-pdo-sqlite  \
    --with-readline  \
    --enable-session  \
    --enable-shmop  \
    --enable-simplexml  \
    --enable-sockets  \
    --enable-sqlite-utf8  \
    --enable-sysvmsg  \
    --enable-sysvsem  \
    --enable-sysvshm  \
    --enable-wddx  \
    --with-libxml-dir  \
    --with-xsl  \
    --enable-zip  \
    --enable-mysqlnd-compression-support  \
    --with-pear  \
    --enable-maintainer-zts  \
    --enable-embed=shared  \
    && make \
    && make install 

#RUN cp php.ini-production /server/php/etc/php.ini 
#ngx_php && nginx 
ENV PHP_BIN /server/php/bin
ENV PHP_INC /server/php/include/php
ENV PHP_LIB /server/php/lib

RUN set -x \ 
    && cd /server/soft/ \
    && git clone https://github.com/rryqszq4/ngx_php \
    && wget "http://nginx.org/download/nginx-1.6.3.tar.gz" \
    && tar -zxvf nginx-1.6.3.tar.gz \
    && cd nginx-1.6.3 \
    && ./configure \
    --user=www --group=www \
    --prefix=/server/nginx \
    --with-ld-opt="-Wl,-rpath,$PHP_LIB" \
    --add-module=/server/soft/ngx_php/dev/ngx_devel_kit \
    --add-module=/server/soft/ngx_php \
    && make \
    && make install 

RUN mv /server/nginx/conf/nginx.conf /server/nginx/conf/nginx.conf.bak
COPY nginx.conf /server/nginx/conf/
RUN ln -s /usr/local/lib/libmcrypt.* /lib64/ 

EXPOSE 80
CMD ["/server/nginx/sbin/nginx"]