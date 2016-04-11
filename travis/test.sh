#!/bin/bash
NGX_PATH=`pwd`'/build/nginx/sbin'
export PATH=${NGX_PATH}:$PATH
prove -r t
echo "test"