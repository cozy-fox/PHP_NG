/**
 *    Copyright(c) 2016 rryqszq4
 *
 *
 */

#include "ngx_http_php_request.h"
#include "ngx_http_php_core.h"
#include "ngx_http_php_module.h"

static int ngx_http_php_request_read_body(ngx_http_request_t *r);
static void ngx_http_php_request_read_body_cb(ngx_http_request_t *r);

static int 
ngx_http_php_request_read_body(ngx_http_request_t *r)
{
	ngx_int_t rc;
	ngx_http_php_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);

	if (r->method != NGX_HTTP_POST && r->method != NGX_HTTP_PUT){
		php_error(E_WARNING, "can't read body");
		return 0;
	}

	rc = ngx_http_read_client_request_body(r, ngx_http_php_request_read_body_cb);

	if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE){
		php_error(E_WARNING, "ngx_http_read_client_request_body failed");
		return 0;
	}

	if (rc == NGX_AGAIN){
		ctx->request_body_more = 1;
	}

	return rc;
}

static void 
ngx_http_php_request_read_body_cb(ngx_http_request_t *r)
{
	ngx_chain_t *cl;
	size_t len;
	u_char *p;
	u_char *buf;

	ngx_http_php_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);

	if (r->request_body == NULL || r->request_body->bufs == NULL){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "This pahse don't have request_body");
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return ;
	}

	cl = r->request_body->bufs;

	if (cl->next == NULL){
		len = cl->buf->last - cl->buf->pos;
		if (len == 0){
			return ;
		}

		ctx->request_body_ctx.data = cl->buf->pos;
		ctx->request_body_ctx.len = len;
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "request_body(%d): %V", len, &ctx->request_body_ctx);
		if (ctx->request_body_more){
			ctx->request_body_more = 0;
			ngx_http_core_run_phases(r);
		}else {
			ngx_http_finalize_request(r, NGX_DONE);
		}
		return ;
	}

	len = 0;
	for (; cl; cl = cl->next){
		len += cl->buf->last - cl->buf->pos;
	}

	if (len == 0){
		return ;
	}

	buf = ngx_palloc(r->pool, len);
	p = buf;
	for (cl = r->request_body->bufs; cl; cl = cl->next){
		p = ngx_copy(p, cl->buf->pos, cl->buf->last - cl->buf->pos);
	}

	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "This pahse don't have request_body");
	ctx->request_body_ctx.data = buf;
	ctx->request_body_ctx.len = len;
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "multi request_body(%d): %V", len, &ctx->request_body_ctx);
	if (ctx->request_body_more){
		ctx->request_body_more = 0;
		ngx_http_core_run_phases(r);
	}else {
		ngx_http_finalize_request(r, NGX_DONE);
	}

	return ;
}

void 
ngx_http_php_request_init(ngx_http_request_t *r TSRMLS_DC)
{
	ngx_http_headers_in_t *headers_in;
	headers_in = &r->headers_in;

	if (r->method == NGX_HTTP_GET){
		SG(request_info).request_method = "GET";
	} else if (r->method == NGX_HTTP_POST){
		SG(request_info).request_method = "POST";

		char *content_type = (char *)headers_in->content_type->value.data;
		SG(request_info).content_type = content_type;
	}

	if (r->args.len > 0){
		SG(request_info).query_string = emalloc(r->args.len+1);
		ngx_cpystrn((u_char *)SG(request_info).query_string, r->args.data, r->args.len+1);

	}

	ngx_http_php_request_context_t *context;
	context = emalloc(sizeof(ngx_http_php_request_context_t));

	SG(server_context) = context;

	ngx_http_php_request_read_body(r);
}

void 
ngx_http_php_request_clean(TSRMLS_D)
{
	if (SG(request_info).query_string){
		efree(SG(request_info).query_string);
		SG(request_info).query_string = NULL;
	}

	if (SG(server_context)){
		efree(SG(server_context));
		SG(server_context) = NULL;
	}

}
















