/**
 *    Copyright(c) 2016 rryqszq4
 *
 *
 */

#include "ngx_http_php_core.h"
#include "ngx_http_php_handler.h"
#include "ngx_http_php_module.h"


ngx_int_t
ngx_http_php_content_handler(ngx_http_request_t *r)
{
	ngx_http_php_loc_conf_t *plcf;
	plcf = ngx_http_get_module_loc_conf(r, ngx_http_php_module);
	if (plcf->content_handler == NULL){
		return NGX_DECLINED;
	}
	return plcf->content_handler(r);
}

ngx_int_t 
ngx_http_php_content_file_handler(ngx_http_request_t *r)
{
	//ngx_http_php_main_conf_t *pmcf = ngx_http_get_module_main_conf(r, ngx_http_php_module);
	ngx_http_php_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_http_php_module);
	ngx_http_php_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);

	ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
	if (ctx == NULL){
		return NGX_ERROR;
	}
	ngx_http_set_ctx(r, ctx, ngx_http_php_module);

	ngx_php_request = r;

	ngx_php_ngx_run(r, plcf->content_code);

	ngx_int_t rc;

	ngx_http_php_rputs_chain_list_t *chain;
	
	ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);
	chain = ctx->rputs_chain;
	if (chain == NULL){
		return NGX_ERROR;
	}

	r->headers_out.content_type.len = sizeof("text/html") - 1;
	r->headers_out.content_type.data = (u_char *)"text/html";
	r->headers_out.status = NGX_HTTP_OK;

	if (r->method == NGX_HTTP_HEAD){
		rc = ngx_http_send_header(r);
		if (rc != NGX_OK){
			return rc;
		}
	}

	if (chain != NULL){
		(*chain->last)->buf->last_buf = 1;
	}

	rc = ngx_http_send_header(r);
	if (rc != NGX_OK){
		return rc;
	}

	ngx_http_output_filter(r, chain->out);

	ngx_http_set_ctx(r, NULL, ngx_http_php_module);

	return NGX_OK;
}

ngx_int_t 
ngx_http_php_content_inline_handler(ngx_http_request_t *r)
{

	ngx_http_php_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_http_php_module);

	ngx_http_php_ctx_t *ctx;
	ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);
	ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
	if (ctx == NULL ){
		return NGX_ERROR;
	}
	ngx_http_set_ctx(r, ctx, ngx_http_php_module);

	ngx_php_request = r;

	//ngx_php_embed_run(r, plcf->content_inline_code);
	ngx_php_ngx_run(r, plcf->content_inline_code);

	ngx_int_t rc;

	ngx_http_php_rputs_chain_list_t *chain;
	
	ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);
	chain = ctx->rputs_chain;
	if (chain == NULL){
		return NGX_ERROR;
	}

	r->headers_out.content_type.len = sizeof("text/html") - 1;
	r->headers_out.content_type.data = (u_char *)"text/html";
	r->headers_out.status = NGX_HTTP_OK;

	if (r->method == NGX_HTTP_HEAD){
		rc = ngx_http_send_header(r);
		if (rc != NGX_OK){
			return rc;
		}
	}

	if (chain != NULL){
		(*chain->last)->buf->last_buf = 1;
	}

	rc = ngx_http_send_header(r);
	if (rc != NGX_OK){
		return rc;
	}

	ngx_http_output_filter(r, chain->out);

	ngx_http_set_ctx(r, NULL, ngx_http_php_module);

	return NGX_OK;
}

