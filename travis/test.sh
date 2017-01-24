#!/bin/bash
# Copyright (c) 2016-2017, rryqszq4 <ngxphp@gmail.com>
echo "ngx_php test ..."
NGX_PATH=`pwd`'/build/nginx/sbin'
${NGX_PATH}/nginx -V
export PATH=${NGX_PATH}:$PATH
prove -r t
#echo "ngx_php test ... done"

#echo "ngx_php test success"