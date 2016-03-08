/**
 *    Copyright(c) 2016 rryqszq4
 *
 *
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_conf_file.h>
#include <nginx.h>

#include "ngx_http_php_module.h"
#include "ngx_http_php_directive.h"

// http init
static ngx_int_t ngx_http_php_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_php_handler_init(ngx_http_core_main_conf_t *cmcf, ngx_http_php_main_conf_t *pmcf);

static void *ngx_http_php_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_php_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child); 

ngx_int_t ngx_php_run(ngx_http_request_t *r, ngx_http_php_code_t *code);

// handler
ngx_int_t ngx_http_php_content_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_php_content_inline_handler(ngx_http_request_t *r);

ngx_http_request_t *ngx_php_request;

static ngx_command_t ngx_http_php_commands[] = {

	{ngx_string("php_content_handler_code"),
	 NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                    |NGX_CONF_TAKE1,
     ngx_http_php_content_inline_phase,
     NGX_HTTP_LOC_CONF_OFFSET,
     0,
     ngx_http_php_content_inline_handler
	},

	ngx_null_command
};

static ngx_http_module_t ngx_http_php_module_ctx = {
	NULL,
	ngx_http_php_init,

	NULL,
	NULL,

	NULL,
	NULL,

	ngx_http_php_create_loc_conf,
	ngx_http_php_merge_loc_conf

};


ngx_module_t ngx_http_php_module = {
	NGX_MODULE_V1,
    &ngx_http_php_module_ctx,    /* module context */
    ngx_http_php_commands,       /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t 
ngx_http_php_init(ngx_conf_t *cf)
{
	ngx_http_core_main_conf_t *cmcf;
	ngx_http_php_main_conf_t *pmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
	pmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_php_module);

	ngx_php_request = NULL;

	if (ngx_http_php_handler_init(cmcf, pmcf) != NGX_OK){
		return NGX_ERROR;
	}

	return NGX_OK;
}

static ngx_int_t 
ngx_http_php_handler_init(ngx_http_core_main_conf_t *cmcf, ngx_http_php_main_conf_t *pmcf)
{
	ngx_int_t i;
	ngx_http_handler_pt *h;
	ngx_http_phases phase;
	ngx_http_phases phases[] = {
		NGX_HTTP_CONTENT_PHASE,
	};
	ngx_int_t phases_c;

	phases_c = sizeof(phases) / sizeof(ngx_http_phases);
	for (i = 0; i < phases_c; i++){
		phase = phases[i];
		switch (phase){
			case NGX_HTTP_CONTENT_PHASE:
				//if (pmcf->enabled_content_handler){
					h = ngx_array_push(&cmcf->phases[phase].handlers);
					if (h == NULL){
						return NGX_ERROR;
					}
					*h = ngx_http_php_content_handler;
				//}
				break;
			default:
				break;
		}
	}

	return NGX_OK;
}

static void *
ngx_http_php_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_php_loc_conf_t *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_php_loc_conf_t));
	if (conf == NULL){
		return NGX_CONF_ERROR;
	}

	conf->content_inline_code = NGX_CONF_UNSET_PTR;

	return conf;
}

static char *
ngx_http_php_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_php_loc_conf_t *prev = parent;
	ngx_http_php_loc_conf_t *conf = child;

	prev->content_inline_code = conf->content_inline_code;

	return NGX_CONF_OK;
}


static int ngx_http_php_code_ub_write(const char *str, unsigned int str_length TSRMLS_DC)
{
	ngx_buf_t *b;
	ngx_http_php_rputs_chain_list_t *chain;
	ngx_http_php_ctx_t *ctx;
	ngx_http_request_t *r;
	u_char *u_str;
	ngx_str_t ns;

	r = ngx_php_request;
	ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);

	ns.data = (u_char *)str;
	ns.len = str_length;

	if (ctx->rputs_chain == NULL){
		chain = ngx_pcalloc(r->pool, sizeof(ngx_http_php_rputs_chain_list_t));
		chain->out = ngx_alloc_chain_link(r->pool);
		chain->last = &chain->out;
	}else {
		chain = ctx->rputs_chain;
		(*chain->last)->next = ngx_alloc_chain_link(r->pool);
		chain->last = &(*chain->last)->next;
	}

	b = ngx_calloc_buf(r->pool);
	(*chain->last)->buf = b;
	(*chain->last)->next = NULL;

	u_str = ngx_pstrdup(r->pool, &ns);
	u_str[ns.len] = '\0';
	(*chain->last)->buf->pos = u_str;
	(*chain->last)->buf->last = u_str + ns.len;
	(*chain->last)->buf->memory = 1;
	ctx->rputs_chain = chain;
	ngx_http_set_ctx(r, ctx, ngx_http_php_module);

	if (r->headers_out.content_length_n == -1){
		r->headers_out.content_length_n += ns.len + 1;
	}else {
		r->headers_out.content_length_n += ns.len;
	}

	return r->headers_out.content_length_n;
}

static void 
ngx_http_php_code_flush(void *server_context)
{
	
	return ;
}

ngx_int_t 
ngx_php_run(ngx_http_request_t *r, ngx_http_php_code_t *code)
{
	
	php_embed_module.ub_write = ngx_http_php_code_ub_write;
	php_embed_module.flush = ngx_http_php_code_flush;
	PHP_EMBED_START_BLOCK(0, NULL);
		zend_eval_string_ex(code->code.string, NULL, "Command line run code", 1 TSRMLS_CC);
	PHP_EMBED_END_BLOCK();

	return 0;
}

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

	ngx_php_run(r, plcf->content_inline_code);

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


















