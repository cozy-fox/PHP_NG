#!/bin/bash
NGX_PATH=`pwd`'/build/nginx/sbin'
`pwd`'/build/nginx/sbin/nginx -V'
export PATH=${NGX_PATH}:$PATH
prove -r t
echo "ngx_php test success"