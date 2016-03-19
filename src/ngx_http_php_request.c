/**
 *    Copyright(c) 2016 rryqszq4
 *
 *
 */

#include "ngx_http_php_request.h"

void 
ngx_http_php_request_init(ngx_http_request_t *r TSRMLS_DC)
{
	SG(request_info).query_string = emalloc(r->args.len + 1);
	memcpy(SG(request_info).query_string, r->args.data, r->args.len + 1);
}

