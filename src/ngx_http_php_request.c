/**
 *    Copyright(c) 2016 rryqszq4
 *
 *
 */

#include "ngx_http_php_request.h"

void 
ngx_http_php_request_init(ngx_http_request_t *r TSRMLS_DC)
{
	if (r->method == NGX_HTTP_GET){
		SG(request_info).request_method = "GET";
	} else if (r->method == NGX_HTTP_POST){
		SG(request_info).request_method = "POST";
	}

	/*SG(request_info).request_uri = (char *)ngx_palloc(r->pool, r->uri.len);
	ngx_memcpy(SG(request_info).request_uri, r->uri.data, r->uri.len);

	SG(request_info).query_string = (char *)ngx_palloc(r->pool, r->args.len);
	ngx_memcpy(SG(request_info).query_string, r->args.data, r->args.len);
	*/
}