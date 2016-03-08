/**
 *    Copyright(c) 2016 rryqszq4
 *
 *
 */

 #ifndef NGX_HTTP_PHP_CORE_H
 #define NGX_HTTP_PHP_CORE_H

#include <ngx_http.h>
#include <php_embed.h>

typedef enum code_type_t {
	NGX_HTTP_PHP_CORE_TYPE_FILE,
	NGX_HTTP_PHP_CODE_TYPE_STRING
} code_type_t;

typedef struct ngx_http_php_code_t {
	union code {
		char *file;
		char *string;
	} code;
	code_type_t code_type;
} ngx_http_php_code_t;

typedef struct ngx_http_php_rputs_chain_list_t {
	ngx_chain_t **last;
	ngx_chain_t *out;
} ngx_http_php_rputs_chain_list_t;

typedef struct ngx_http_php_ctx_t {
	ngx_http_php_rputs_chain_list_t *rputs_chain;
} ngx_http_php_ctx_t;

ngx_http_php_code_t *ngx_http_php_code_from_string(ngx_pool_t *pool, ngx_str_t *code_str);



#endif