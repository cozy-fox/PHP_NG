/**
 *    Copyright(c) 2016 rryqszq4
 *
 *
 */

#include "ngx_http_php_subrequest.h"
#include "ngx_http_php_request.h"

ngx_int_t 
ngx_http_php_subrequest_post(ngx_http_request_t *r)
{
	ngx_int_t rc;

	/*ngx_http_php_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);
	if (ctx == NULL){
		ctx = ngx_palloc(r->pool, sizeof(ngx_http_php_ctx_t));
		if (ctx == NULL){
			return NGX_ERROR;
		}
		ngx_http_set_ctx(r, ctx, ngx_http_php_module);
	}*/

	r->count++;
	ngx_http_php_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);

	//ctx->enable_async = 1;

	//ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "sub uri %s", ctx->capture_uri.data);

	ngx_http_post_subrequest_t *psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
	if (psr == NULL){
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	psr->handler = ngx_http_php_subrequest_post_handler;
	psr->data = ctx;

	ngx_str_t sub_location;
	sub_location.len = ctx->capture_uri.len;
	sub_location.data = ngx_palloc(r->pool, sub_location.len);
	ngx_snprintf(sub_location.data, sub_location.len, "%V", &ctx->capture_uri);

	ngx_http_request_t *sr;
	rc = ngx_http_subrequest(r, &sub_location, NULL, &sr, psr, NGX_HTTP_SUBREQUEST_IN_MEMORY);
	if (rc != NGX_OK){
		return NGX_ERROR;
	}

	return NGX_OK;
}


ngx_int_t 
ngx_http_php_subrequest_post_handler(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
	ngx_http_request_t *pr = r->parent;
	ngx_php_request = pr;

	ngx_http_php_ctx_t *ctx = ngx_http_get_module_ctx(ngx_php_request, ngx_http_php_module);

	pr->headers_out.status = r->headers_out.status;

	if (r->headers_out.status == NGX_HTTP_OK){
		//int flag = 0;
		//ngx_buf_t *pRecvBuf = &r->upstream->buffer;
		//ngx_log_error(NGX_LOG_ERR, pr->connection->log, 0, "%s", pRecvBuf->pos);
		/*for(;pRecvBuf->pos != pRecvBuf->last;pRecvBuf->pos++){  
                if(*pRecvBuf->pos == ','||*pRecvBuf->pos == '\"'){  
                        if(flag>0) ctx->stock[flag-1].len = pRecvBuf->pos - ctx->stock[flag-1].data;  
                        flag++;  
                        ctx->stock[flag-1].data = pRecvBuf->pos + 1;  
                }  

                if(flag>6) break;  
        }*/

        /*ngx_buf_t *b = &r->upstream->buffer;

        ngx_http_php_rputs_chain_list_t *chain;

        if (ctx->rputs_chain == NULL){
			chain = ngx_pcalloc(r->pool, sizeof(ngx_http_php_rputs_chain_list_t));
			chain->out = ngx_alloc_chain_link(r->pool);
			chain->last = &chain->out;
		}else {
			chain = ctx->rputs_chain;
			(*chain->last)->next = ngx_alloc_chain_link(r->pool);
			chain->last = &(*chain->last)->next;
		}

		(*chain->last)->buf = b;
		(*chain->last)->next = NULL;

		(*chain->last)->buf->pos = b->pos;
		(*chain->last)->buf->last = b->last;
		(*chain->last)->buf->memory = 1;
		ctx->rputs_chain = chain;
		ngx_http_set_ctx(r, ctx, ngx_http_php_module);

		if (pr->headers_out.content_length_n == -1){
			pr->headers_out.content_length_n += b->last - b->pos + 1;
		}else {
			pr->headers_out.content_length_n += b->last - b->pos;
		}*/

		//ctx->capture_buf = &r->upstream->buffer;

		ctx->capture_str.len = (&r->upstream->buffer)->last - (&r->upstream->buffer)->pos;
		ctx->capture_str.data = (&r->upstream->buffer)->pos;
		//ngx_log_error(NGX_LOG_ERR, pr->connection->log, 0, "%s", (&r->upstream->buffer)->pos);

		/*NGX_HTTP_PHP_NGX_INIT;

			zend_eval_string_ex("echo 0;", NULL, "ngx_php run code", 1 TSRMLS_CC);

		NGX_HTTP_PHP_NGX_SHUTDOWN;*/

	}

	pthread_mutex_lock(&(ctx->mutex));
	pthread_cond_signal(&(ctx->cond));
	pthread_mutex_unlock(&(ctx->mutex));
	pthread_join(ctx->pthread_id, NULL);

	pr->write_event_handler = ngx_http_php_subrequest_post_parent;

	/*sleep(5);
	pthread_mutex_lock(&(ctx->mutex));
	pthread_cond_signal(&ctx->cond);
	pthread_mutex_unlock(&(ctx->mutex));*/

	//r->main->count++;

	return NGX_OK;
}


void 
ngx_http_php_subrequest_post_parent(ngx_http_request_t *r)
{

	//TSRMLS_FETCH();
	if (r->headers_out.status != NGX_HTTP_OK){
		ngx_http_finalize_request(r, r->headers_out.status);
		return ;
	}

	ngx_php_request = r;

	ngx_http_php_ctx_t *ctx;
	
	ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);



	//NGX_HTTP_PHP_NGX_INIT;
	/*zend_first_try {
		//zval *args[1];
		//zval uri;
		zval retval;

		//args[0] = &uri;
		//ZVAL_STRINGL(args[0], (char *)ctx->capture_buf->pos, ctx->capture_buf->last - ctx->capture_buf->pos, 1);

		if (call_user_function(EG(function_table), NULL, ctx->closure, &retval, 0, NULL TSRMLS_CC) == FAILURE)
  		{
    		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failed calling closure");
    		//return ;
  		}
  		//zval_dtor(args[0]);
  		zval_dtor(&retval);
		//zend_eval_string_ex("echo 0;", NULL, "ngx_php run code", 1 TSRMLS_CC);
	} zend_catch {		
	} zend_end_try();*/

	//zend_eval_string_ex("echo 0;", NULL, "ngx_php run code", 1 TSRMLS_CC);

	//NGX_HTTP_PHP_NGX_SHUTDOWN;

	//ngx_http_php_request_clean(TSRMLS_C);
	//php_request_shutdown_for_exec((void *)0);

	//NGX_HTTP_PHP_NGX_INIT;
	//NGX_HTTP_PHP_NGX_SHUTDOWN;
	
	//ngx_http_php_request_init(r TSRMLS_CC);

	//ngx_http_php_request_clean(TSRMLS_C);

	//php_ngx_request_init(TSRMLS_C);
	//php_ngx_request_shutdown(TSRMLS_C);

	//ngx_http_php_request_clean(TSRMLS_C);
	//php_ngx_request_shutdown(TSRMLS_C);

	//php_request_startup_for_hook(TSRMLS_C);
	
	//php_request_shutdown_for_exec((void *)0);


	/*ngx_http_mytest_ctx_t *myctx = ngx_http_get_module_ctx(r,ngx_http_php_module);  
    ngx_str_t output_format = ngx_string("stock[%V],Today current price: %V,volum: %V");  
    int bodylen = output_format.len + myctx->stock[0].len + myctx->stock[1].len+myctx->stock[4].len - 6;  
    r->headers_out.content_length_n = bodylen;  
    ngx_buf_t *b = ngx_create_temp_buf(r->pool,bodylen);  
    ngx_snprintf(b->pos,bodylen,(char*)output_format.data,&myctx->stock[0],&myctx->stock[1],&myctx->stock[4]);  
    b->last = b->pos + bodylen;  
    b->last_buf = 1;  
    ngx_chain_t out;  
    out.buf = b;  
    out.next = NULL;  
    static ngx_str_t type = ngx_string("text/plain; charset=GBK");  
    r->headers_out.content_type = type;  
    r->headers_out.status = NGX_HTTP_OK;  
    r->connection->buffered |= NGX_HTTP_WRITE_BUFFERED;  
    ngx_int_t ret = ngx_http_send_header(r);
    ret = ngx_http_output_filter(r,&out);  
    ngx_http_finalize_request(r,ret);*/

    ngx_int_t rc;
	//ngx_http_php_ctx_t *ctx;
    ngx_http_php_rputs_chain_list_t *chain;
	
	//ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);

	chain = ctx->rputs_chain;
	
	if (ctx->rputs_chain == NULL){
		ngx_buf_t *b;
		ngx_str_t ns;
		u_char *u_str;
		ns.data = (u_char *)" ";
		ns.len = 1;
		
		chain = ngx_pcalloc(r->pool, sizeof(ngx_http_php_rputs_chain_list_t));
		chain->out = ngx_alloc_chain_link(r->pool);
		chain->last = &chain->out;
	
		b = ngx_calloc_buf(r->pool);
		(*chain->last)->buf = b;
		(*chain->last)->next = NULL;

		u_str = ngx_pstrdup(r->pool, &ns);
		//u_str[ns.len] = '\0';
		(*chain->last)->buf->pos = u_str;
		(*chain->last)->buf->last = u_str + ns.len;
		(*chain->last)->buf->memory = 1;
		ctx->rputs_chain = chain;

		if (r->headers_out.content_length_n == -1){
			r->headers_out.content_length_n += ns.len + 1;
		}else {
			r->headers_out.content_length_n += ns.len;
		}
	}else {
		/*ngx_buf_t *b;
		ngx_str_t ns;
		u_char *u_str;
		ns.data = (u_char *)" ";
		ns.len = 1;
		chain = ngx_pcalloc(r->pool, sizeof(ngx_http_php_rputs_chain_list_t));
		chain->out = ngx_alloc_chain_link(r->pool);
		chain->last = &chain->out;

		b = ngx_calloc_buf(r->pool);
			(*chain->last)->buf = b;
			(*chain->last)->next = NULL;

			u_str = ngx_pstrdup(r->pool, &ns);
			//u_str[ns.len] = '\0';
			(*chain->last)->buf->pos = u_str;
			(*chain->last)->buf->last = u_str + ns.len;
			(*chain->last)->buf->memory = 1;
			ctx->rputs_chain = chain;

			if (r->headers_out.content_length_n == -1){
				r->headers_out.content_length_n += ns.len + 1;
			}else {
				r->headers_out.content_length_n += ns.len;
			}

	    static ngx_str_t type = ngx_string("text/plain; charset=GBK");  
	    r->headers_out.content_type = type;  
	    r->headers_out.status = NGX_HTTP_OK;  
	    r->connection->buffered |= NGX_HTTP_WRITE_BUFFERED;*/
	}

	//r->headers_out.content_type.len = sizeof("text/html") - 1;
	//r->headers_out.content_type.data = (u_char *)"text/html";  

	if (!r->headers_out.status){
		r->headers_out.status = NGX_HTTP_OK;
	}

	if (chain != NULL){
		(*chain->last)->buf->last_buf = 1;
	}

	rc = ngx_http_send_header(r);

	rc = ngx_http_output_filter(r, chain->out);

	ngx_http_set_ctx(r, NULL, ngx_http_php_module);

	ngx_http_finalize_request(r,rc);

	//ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%d", r->headers_out.status);
}


ngx_int_t 
ngx_http_php_subrequest_post_multi(ngx_http_request_t *r)
{
	ngx_php_request = r;

	ngx_uint_t rc;
	//ngx_uint_t i;

	ngx_http_php_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);

	ngx_http_php_capture_node_t *capture_node = ctx->capture_multi->elts;

	capture_node = capture_node + ctx->capture_multi_complete_total;

	//for (i = 0; i < ctx->capture_multi->nelts; i++,capture_node++){
		//r->count++;

	ngx_http_post_subrequest_t *psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
	if (psr == NULL){
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	psr->handler = ngx_http_php_subrequest_post_multi_handler;
	psr->data = ctx;

	ngx_str_t sub_location;
	sub_location.len = capture_node->capture_uri.len;
	sub_location.data = ngx_palloc(r->pool, sub_location.len);
	ngx_snprintf(sub_location.data, sub_location.len, "%V", &capture_node->capture_uri);

	ngx_http_request_t *sr;
	rc = ngx_http_subrequest(r, &sub_location, NULL, &sr, psr, NGX_HTTP_SUBREQUEST_IN_MEMORY);
	if (rc != NGX_OK){
		return NGX_ERROR;
	}
	//}

	return NGX_OK;

}

ngx_int_t 
ngx_http_php_subrequest_post_multi_handler(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
	ngx_http_request_t *pr = r->parent;
	ngx_php_request = pr;

	ngx_http_php_ctx_t *ctx = ngx_http_get_module_ctx(pr, ngx_http_php_module);

	pr->headers_out.status = r->headers_out.status;

	if (r->headers_out.status == NGX_HTTP_OK){

		ngx_http_php_capture_node_t *capture_node = ctx->capture_multi->elts;

		capture_node = capture_node + ctx->capture_multi_complete_total;

		capture_node->capture_str.len = (&r->upstream->buffer)->last - (&r->upstream->buffer)->pos;
		capture_node->capture_str.data = (&r->upstream->buffer)->pos;

		ctx->capture_multi_complete_total++;

	}

	if (ctx->capture_multi_complete_total >= ctx->capture_multi->nelts){

		pthread_mutex_lock(&(ctx->mutex));
		pthread_cond_signal(&(ctx->cond));
		pthread_mutex_unlock(&(ctx->mutex));
		pthread_join(ctx->pthread_id, NULL);

		pr->write_event_handler = (ngx_http_event_handler_pt)ngx_http_php_subrequest_post_multi_parent;

	}else {
		pr->write_event_handler = (ngx_http_event_handler_pt)ngx_http_php_subrequest_post_multi_parent;
	}

	return NGX_OK;
}


ngx_int_t 
ngx_http_php_subrequest_post_multi_parent(ngx_http_request_t *r)
{

	//TSRMLS_FETCH();
	/*if (r->headers_out.status != NGX_HTTP_OK){
		ngx_http_finalize_request(r, r->headers_out.status);
		return ;
	}*/

	ngx_php_request = r;

	ngx_http_php_ctx_t *ctx;
	
	ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);

	if (ctx->capture_multi_complete_total >= ctx->capture_multi->nelts){
		r->main->count++;

	    ngx_int_t rc;
		//ngx_http_php_ctx_t *ctx;
	    ngx_http_php_rputs_chain_list_t *chain;
		
		//ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);

		chain = ctx->rputs_chain;
		
		if (ctx->rputs_chain == NULL){
			ngx_buf_t *b;
			ngx_str_t ns;
			u_char *u_str;
			ns.data = (u_char *)" ";
			ns.len = 1;
			
			chain = ngx_pcalloc(r->pool, sizeof(ngx_http_php_rputs_chain_list_t));
			chain->out = ngx_alloc_chain_link(r->pool);
			chain->last = &chain->out;
		
			b = ngx_calloc_buf(r->pool);
			(*chain->last)->buf = b;
			(*chain->last)->next = NULL;

			u_str = ngx_pstrdup(r->pool, &ns);
			//u_str[ns.len] = '\0';
			(*chain->last)->buf->pos = u_str;
			(*chain->last)->buf->last = u_str + ns.len;
			(*chain->last)->buf->memory = 1;
			ctx->rputs_chain = chain;

			if (r->headers_out.content_length_n == -1){
				r->headers_out.content_length_n += ns.len + 1;
			}else {
				r->headers_out.content_length_n += ns.len;
			}
		}else {
			
		}

		//r->headers_out.content_type.len = sizeof("text/html") - 1;
		//r->headers_out.content_type.data = (u_char *)"text/html";  

		if (!r->headers_out.status){
			r->headers_out.status = NGX_HTTP_OK;
		}

		if (chain != NULL){
			(*chain->last)->buf->last_buf = 1;
		}

		rc = ngx_http_send_header(r);

		rc = ngx_http_output_filter(r, chain->out);

		ngx_http_set_ctx(r, NULL, ngx_http_php_module);

		ngx_http_finalize_request(r,rc);

		return NGX_OK;
	}else {

		ngx_http_php_subrequest_post_multi(r);
		return NGX_DONE;
	}
}




