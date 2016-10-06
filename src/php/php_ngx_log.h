/**
 *    Copyright(c) 2016 rryqszq4
 *
 *
 */

#ifndef _PHP_NGX_LOG_H
#define _PHP_NGX_LOG_H

#include <ngx_http.h>
 
#include <php.h>
#include <php_ini.h>
#include <ext/standard/info.h>

PHP_METHOD(ngx_log, error);

void php_ngx_log_init(int module_number TSRMLS_DC);

#endif