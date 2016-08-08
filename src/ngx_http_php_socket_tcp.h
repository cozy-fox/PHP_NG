/**
 *    Copyright(c) 2016 rryqszq4
 *
 *
 */

#ifndef NGX_HTTP_PHP_SOCKET_TCP_H
#define NGX_HTTP_PHP_SOCKET_TCP_H

#include "ngx_http_php_module.h"

ngx_int_t ngx_http_php_socket_tcp(ngx_http_request_t *r);

ngx_int_t ngx_http_php_socket_connect(ngx_http_request_t *r);

ngx_int_t ngx_http_php_socket_tcp_send(ngx_http_request_t *r);

ngx_int_t ngx_http_php_socket_tcp_receive(ngx_http_request_t *r);

ngx_int_t ngx_http_php_socket_tcp_receive_parse(ngx_http_request_t *r);

void ngx_http_php_socket_tcp_close(ngx_http_request_t *r, ngx_int_t rc);

ngx_int_t ngx_http_php_socket_tcp_handler(ngx_http_request_t *r);

#endif