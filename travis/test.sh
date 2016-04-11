#!/bin/bash
NGX_PATH=`pwd`'/nginx/sbin'
`pwd`'/nginx/sbin/nginx -V'
export PATH=${NGX_PATH}:$PATH
prove -r t
echo "ngx_php test success"