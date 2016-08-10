docker build  -t your_name:ngx_php .
docker run -d -p 8080:80 -it --name t2 your_name:ngx_php 

