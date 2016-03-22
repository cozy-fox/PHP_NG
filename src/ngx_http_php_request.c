/**
 *    Copyright(c) 2016 rryqszq4
 *
 *
 */

#include "ngx_http_php_request.h"

void 
ngx_http_php_request_init(ngx_http_request_t *r TSRMLS_DC)
{
	if (r->args.len > 0){
		SG(request_info).query_string = emalloc(r->args.len+1);
		ngx_cpystrn((u_char *)SG(request_info).query_string, r->args.data, r->args.len+1);

	}
}

void 
ngx_http_php_request_clean(TSRMLS_D){
	if (SG(request_info).query_string){
		efree(SG(request_info).query_string);
	}
}

