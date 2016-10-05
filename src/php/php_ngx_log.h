/**
 *    Copyright(c) 2016 rryqszq4
 *
 *
 */

#ifndef _PHP_NGX_SOCKET_TCP_H
#define _PHP_NGX_SOCKET_TCP_H

#include <ngx_http.h>
 
#include <php.h>
#include <php_ini.h>
#include <ext/standard/info.h>

PHP_METHOD(ngx_log, log);

void ngx_log_init(int module_number TSRMLS_DC);

#endif