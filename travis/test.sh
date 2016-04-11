#!/bin/bash
cd ..
pwd
NGX_PATH=`pwd`'/nginx/sbin'
export PATH=${NGX_PATH}:$PATH
prove -r t
echo "ngx_php test success"