#!/bin/bash
# Copyright (c) 2016-2017, rryqszq4 <ngxphp@gmail.com>
NGX_PATH='/usr/local/nginx_php_dev/sbin'
ls ${NGX_PATH}
${NGX_PATH}/nginx -V
export PATH=${NGX_PATH}:$PATH
prove -r -p t
if [ $? -eq 0 ];then
    echo $?;
else
    echo $?;
fi