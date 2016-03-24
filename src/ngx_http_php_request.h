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

typedef struct _ngx_http_php_request_context_t {

	
	
} ngx_http_php_request_context_t;

void ngx_http_php_request_init(ngx_http_request_t *r TSRMLS_DC);
void ngx_http_php_request_clean(TSRMLS_D);

#endif