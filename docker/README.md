Installation
-------
```sh

docker build  -t your_name:ngx_php .

docker run -d -p 8080:80 -it --name ngx_php your_name:ngx_php 

curl http://127.0.0.1:8080/php

