#!/bin/bash
echo "ngx_php test ..."
NGX_PATH=`pwd`'/build/nginx/sbin'
${NGX_PATH}/nginx -V
export PATH=${NGX_PATH}:$PATH
prove -r t
echo "ngx_php test ... done"

echo "ngx_php test success"