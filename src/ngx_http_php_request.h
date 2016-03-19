/**
 *    Copyright(c) 2016 rryqszq4
 *
 *
 */

#ifndef NGX_HTTP_PHP_REQUEST_H
#define NGX_HTTP_PHP_REQUEST_H

#include <ngx_http.h>

#include <php.h>
#include <SAPI.h>
#include <php_main.h>
#include <php_variables.h>


void ngx_http_php_request_init(ngx_http_request_t *r TSRMLS_DC);

#endif