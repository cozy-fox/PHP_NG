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
	rc = ngx_http_php_subrequest(r, &sub_location, NULL, &sr, psr, NGX_HTTP_SUBREQUEST_IN_MEMORY);
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

	pr->write_event_handler = (ngx_http_event_handler_pt)ngx_http_php_subrequest_post_parent;

	/*sleep(5);
	pthread_mutex_lock(&(ctx->mutex));
	pthread_cond_signal(&ctx->cond);
	pthread_mutex_unlock(&(ctx->mutex));*/

	//r->main->count++;

	return NGX_OK;
}


ngx_int_t 
ngx_http_php_subrequest_post_parent(ngx_http_request_t *r)
{

	//TSRMLS_FETCH();
	if (r->headers_out.status != NGX_HTTP_OK){
		ngx_http_finalize_request(r, r->headers_out.status);
		return NGX_ERROR;
	}

	ngx_php_request = r;

	ngx_http_php_ctx_t *ctx;
	
	ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);

    ctx->enable_async = 0;
    ngx_http_set_ctx(r, ctx, ngx_http_php_module);

    pthread_mutex_lock(&(ctx->mutex));
    pthread_cond_signal(&(ctx->cond));
    pthread_mutex_unlock(&(ctx->mutex));

    for ( ;; ){
        usleep(1);
        //ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);
        //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "subrequests post parent %d %d", ctx->enable_async, ctx->enable_thread);

        if (ctx->enable_async == 1 || ctx->enable_thread == 0){
            //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "main %d", ctx->enable_async);
            break;
        }
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "over %d %d", ctx->enable_async, ctx->enable_thread);


    if (ctx->enable_async == 1){
        r->count--;
        if (ctx->is_capture_multi == 0){
            ngx_http_php_subrequest_post(r);
        } else {
            ngx_http_php_subrequest_post_multi(r);
        }
        return NGX_DONE;
    }

    //if (ctx->enable_thread == 0){
    pthread_join(ctx->pthread_id, NULL);
    //}


    pthread_cond_destroy(&(ctx->cond));
    pthread_mutex_destroy(&(ctx->mutex));

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
    return NGX_OK;
}


ngx_int_t 
ngx_http_php_subrequest_post_multi(ngx_http_request_t *r)
{
	ngx_php_request = r;

	ngx_uint_t rc;

	ngx_http_php_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);

	ngx_http_php_capture_node_t *capture_node = ctx->capture_multi->elts;

	//capture_node = capture_node + ctx->capture_multi_complete_total;

	r->count = r->count + (2 - ctx->capture_multi->nelts);

	ngx_uint_t i;
	for (i = 0; i < ctx->capture_multi->nelts; i++,capture_node++){
		//r->count++;

		//ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "res => %d", i);

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
		rc = ngx_http_php_subrequest(r, &sub_location, NULL, &sr, psr, NGX_HTTP_SUBREQUEST_IN_MEMORY);

		if (rc != NGX_OK){
			return NGX_ERROR;
		}
	}

	//ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_subrequest %d",r->main->count);

	return NGX_OK;

}

ngx_int_t 
ngx_http_php_subrequest_post_multi_handler(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
	ngx_http_request_t *pr = r->parent;
	ngx_php_request = pr;

	//ngx_http_php_ctx_t *ctx = ngx_http_get_module_ctx(pr, ngx_http_php_module);
	ngx_http_php_ctx_t *ctx;
	ctx = (ngx_http_php_ctx_t *)data;

	pr->headers_out.status = r->headers_out.status;

	if (r->headers_out.status == NGX_HTTP_OK){

		ngx_http_php_capture_node_t *capture_node = ctx->capture_multi->elts;

		capture_node = capture_node + ctx->capture_multi_complete_total;

		capture_node->capture_str.len = (&r->upstream->buffer)->last - (&r->upstream->buffer)->pos;
		capture_node->capture_str.data = (&r->upstream->buffer)->pos;

		ctx->capture_multi_complete_total++;
		//ngx_http_set_ctx(pr, ctx, ngx_http_php_module);
		//ngx_log_error(NGX_LOG_ERR, pr->connection->log, 0, "sub :=> %d", ctx->capture_multi_complete_total);

	}

	if (ctx->capture_multi_complete_total >= ctx->capture_multi->nelts){

		pthread_mutex_lock(&(ctx->mutex));
		pthread_cond_signal(&(ctx->cond));
		pthread_mutex_unlock(&(ctx->mutex));
		pthread_join(ctx->pthread_id, NULL);

		ctx->is_capture_multi_complete = 1;

		ngx_http_set_ctx(pr, ctx, ngx_http_php_module);

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

	if (ctx->is_capture_multi_complete == 1){
        pthread_cond_destroy(&(ctx->cond));
        pthread_mutex_destroy(&(ctx->mutex));

		//ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "total :=> %d", ctx->capture_multi_complete_total);
		//r->main->count++;

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

		//ngx_http_php_subrequest_post_multi(r);
		return NGX_DONE;
	}

}

ngx_int_t
ngx_http_php_subrequest(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args, ngx_http_request_t **psr,
    ngx_http_post_subrequest_t *ps, ngx_uint_t flags)
{
    ngx_time_t                    *tp;
    ngx_connection_t              *c;
    ngx_http_request_t            *sr;
    ngx_http_core_srv_conf_t      *cscf;
    //ngx_http_postponed_request_t  *pr, *p;

    r->main->subrequests--;

    if (r->main->subrequests == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "subrequests cycle while processing \"%V\"", uri);
        r->main->subrequests = 1;
        return NGX_ERROR;
    }

    sr = ngx_pcalloc(r->pool, sizeof(ngx_http_request_t));
    if (sr == NULL) {
        return NGX_ERROR;
    }

    sr->signature = NGX_HTTP_MODULE;

    c = r->connection;
    sr->connection = c;

    sr->ctx = ngx_pcalloc(r->pool, sizeof(void *) * ngx_http_max_module);
    if (sr->ctx == NULL) {
        return NGX_ERROR;
    }

    if (ngx_list_init(&sr->headers_out.headers, r->pool, 20,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
    sr->main_conf = cscf->ctx->main_conf;
    sr->srv_conf = cscf->ctx->srv_conf;
    sr->loc_conf = cscf->ctx->loc_conf;

    sr->pool = r->pool;

    sr->headers_in.content_length_n = -1;
    sr->headers_in.keep_alive_n = -1;

    //sr->headers_in = r->headers_in;

    ngx_http_clear_content_length(sr);
    ngx_http_clear_accept_ranges(sr);
    ngx_http_clear_last_modified(sr);

    sr->request_body = r->request_body;

#if (NGX_HTTP_SPDY)
    sr->spdy_stream = r->spdy_stream;
#endif

    sr->method = NGX_HTTP_GET;
    sr->http_version = r->http_version;

    sr->request_line = r->request_line;
    sr->uri = *uri;

    if (args) {
        sr->args = *args;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http subrequest \"%V?%V\"", uri, &sr->args);

    sr->subrequest_in_memory = (flags & NGX_HTTP_SUBREQUEST_IN_MEMORY) != 0;
    sr->waited = (flags & NGX_HTTP_SUBREQUEST_WAITED) != 0;

    sr->unparsed_uri = r->unparsed_uri;
    sr->method_name = ngx_http_core_get_method;
    sr->http_protocol = r->http_protocol;

    ngx_http_set_exten(sr);

    sr->main = r->main;
    sr->parent = r;
    sr->post_subrequest = ps;
    sr->read_event_handler = ngx_http_request_empty_handler;
    sr->write_event_handler = ngx_http_handler;

    //if (c->data == r && r->postponed == NULL) {
        c->data = sr;
    //}

    sr->variables = r->variables;

    sr->log_handler = r->log_handler;

    /*pr = ngx_palloc(r->pool, sizeof(ngx_http_postponed_request_t));
    if (pr == NULL) {
        return NGX_ERROR;
    }

    pr->request = sr;
    pr->out = NULL;
    pr->next = NULL;*/

    //if (r->postponed) {
    //    for (p = r->postponed; p->next; p = p->next) { /* void */ }
    //    p->next = pr;

    //} else {
    //    r->postponed = pr;
    //}

    sr->internal = 1;

    sr->discard_body = r->discard_body;
    sr->expect_tested = 1;
    sr->main_filter_need_in_memory = r->main_filter_need_in_memory;

    sr->uri_changes = NGX_HTTP_MAX_URI_CHANGES + 1;

    tp = ngx_timeofday();
    sr->start_sec = tp->sec;
    sr->start_msec = tp->msec;

    r->main->count++;

    *psr = sr;

    return ngx_http_post_request(sr, NULL);
}




