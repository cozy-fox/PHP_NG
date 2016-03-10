/**
 *    Copyright(c) 2016 rryqszq4
 *
 *
 */

#ifndef _PHP_NGX_H_
#define _PHP_NGX_H_

#include <php.h>
#include <SAPI.h>
#include <ext/standard/php_standard.h>


int php_ngx_module_init(TSRMLS_D);
void php_ngx_module_shutdown(TSRMLS_D);

int php_ngx_request_init(TSRMLS_D);
void php_ngx_request_shutdown(TSRMLS_D);

extern sapi_module_struct php_ngx_module;
#endif