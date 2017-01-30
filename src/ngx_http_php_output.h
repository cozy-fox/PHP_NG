/**
 *    Copyright(c) 2016-2017 rryqszq4
 *
 *
 */

#ifndef NGX_HTTP_PHP_OUTPUT_H
#define NGX_HTTP_PHP_OUTPUT_H

#include <nginx.h>
#include <ngx_http.h>

void ngx_http_php_set_output(char *buffer, int buffer_len);

void ngx_http_php_check_output_empty();

#endif