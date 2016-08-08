/**
 *    Copyright(c) 2016 rryqszq4
 *
 *
 */

#include "ngx_http_php_socket_tcp.h"
#include "ngx_http_php_subrequest.h"

ngx_int_t 
ngx_http_php_socket_tcp(ngx_http_request_t *r)
{
    ngx_http_php_socket_connect(r);
    return NGX_OK;
}

ngx_int_t 
ngx_http_php_socket_connect(ngx_http_request_t *r)
{
    ngx_http_php_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);

    if (ngx_http_upstream_create(r) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_upstream_create() failed");
        return NGX_ERROR;
    }

    ngx_http_upstream_t *u = r->upstream;
    u->conf->connect_timeout = 60000;
    u->conf->send_timeout = 60000;
    u->conf->read_timeout = 60000;
    u->conf->store_access = 0600;

    u->conf->buffering = 0;
    u->conf->bufs.num = 8;
    u->conf->bufs.size = ngx_pagesize;
    u->conf->buffer_size = ngx_pagesize;
    u->conf->busy_buffers_size = 2 * ngx_pagesize;
    u->conf->temp_file_write_size = 2 * ngx_pagesize;
    u->conf->max_temp_file_size = 1024 * 1024 * 1024;

    u->conf->hide_headers = NGX_CONF_UNSET_PTR;
    u->conf->pass_headers = NGX_CONF_UNSET_PTR;

    u->buffering = 0;

    u->resolved = (ngx_http_upstream_resolved_t *)ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if (u->resolved == NULL){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_pcalloc resolved error. %s.", strerror(errno));
        return NGX_ERROR;
    }

    static struct sockaddr_in backendSockAddr;
    struct hostent *pHost = gethostbyname((char*)ctx->host.data);
    if (pHost == NULL){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "gethostbyname fail. %s", strerror(errno));
        return NGX_ERROR;
    }

    backendSockAddr.sin_family = AF_INET;
    backendSockAddr.sin_port = htons((in_port_t) ctx->port);

    u->resolved->sockaddr = (struct sockaddr *)&backendSockAddr;
    u->resolved->socklen = sizeof(struct sockaddr_in);
    u->resolved->naddrs = 1;

    u->create_request = ngx_http_php_socket_tcp_send;
    u->process_header = ngx_http_php_socket_tcp_receive;
    u->finalize_request = ngx_http_php_socket_tcp_close;

    r->main->count++;

    ngx_http_upstream_init(r);

    return NGX_OK;
}

ngx_int_t 
ngx_http_php_socket_tcp_send(ngx_http_request_t *r)
{
    //ngx_http_php_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);

    ngx_str_t backendQueryLine =
        ngx_string("GET /search?q=%V HTTP/1.1\r\nHost: www.sina.com\r\nConnection: close\r\n\r\n");
    ngx_int_t queryLineLen = backendQueryLine.len + r->args.len - 2;

    ngx_buf_t* b = ngx_create_temp_buf(r->pool, queryLineLen);
    if (b == NULL)
        return NGX_ERROR;
    
    b->last = b->pos + queryLineLen;

    ngx_snprintf(b->pos, queryLineLen, (char*)backendQueryLine.data, &r->args); 
              
    r->upstream->request_bufs = ngx_alloc_chain_link(r->pool);
    if (r->upstream->request_bufs == NULL)
        return NGX_ERROR;

    r->upstream->request_bufs->buf = b;
    r->upstream->request_bufs->next = NULL;

    r->upstream->request_sent = 0;
    r->upstream->header_sent = 0;

    r->header_hash = 1;

    return NGX_OK;
}

ngx_int_t 
ngx_http_php_socket_tcp_receive(ngx_http_request_t *r)
{
    size_t len;
    ngx_int_t rc;
    ngx_http_upstream_t *u;

    ngx_http_php_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);
    if (ctx == NULL){
        return NGX_ERROR;
    }

    u = r->upstream;

    rc = ngx_http_parse_status_line(r, &u->buffer, &ctx->receive_status);

    if (rc == NGX_AGAIN){
        return rc;
    }

    if (u->state)
    {
        u->state->status = ctx->receive_status.code;
    }

    u->headers_in.status_n = ctx->receive_status.code;

    len = ctx->receive_status.end - ctx->receive_status.start;
    u->headers_in.status_line.len = len;

    u->headers_in.status_line.data = ngx_pnalloc(r->pool, len);
    if (u->headers_in.status_line.data == NULL)
    {
        return NGX_ERROR;
    }

    ngx_memcpy(u->headers_in.status_line.data, ctx->receive_status.start, len);

    u->process_header = ngx_http_php_socket_tcp_receive_parse;

    return ngx_http_php_socket_tcp_receive_parse(r);

}

ngx_int_t
ngx_http_php_socket_tcp_receive_parse(ngx_http_request_t *r)
{
    ngx_int_t                       rc;
    ngx_table_elt_t                *h;
    //ngx_http_upstream_header_t     *hh;

    ngx_http_php_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);

    ctx->enable_upstream = 0;
    ngx_http_set_ctx(r, ctx, ngx_http_php_module);

    pthread_mutex_lock(&(ctx->mutex));
    pthread_cond_signal(&(ctx->cond));
    pthread_mutex_unlock(&(ctx->mutex));

    //循环的解析所有的http头部
    for ( ;; ) {
        // http框架提供了基础性的ngx_http_parse_header_line方法，它用于解析http头部
        rc = ngx_http_parse_header_line(r, &r->upstream->buffer, 1);
        //返回NGX_OK表示解析出一行http头部
        if (rc == NGX_OK)
        {
            //向headers_in.headers这个ngx_list_t链表中添加http头部
            h = ngx_list_push(&r->upstream->headers_in.headers);
            if (h == NULL)
            {
                return NGX_ERROR;
            }
            //以下开始构造刚刚添加到headers链表中的http头部
            h->hash = r->header_hash;

            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;
            
            //必须由内存池中分配解析出的这一行信息，存放解析出的这一行http头部的内存
            h->key.data = ngx_pnalloc(r->pool,
                                      h->key.len + 1 + h->value.len + 1 + h->key.len);
            if (h->key.data == NULL)
            {
                return NGX_ERROR;
            }

            /* key + value + 小写key */
            h->value.data = h->key.data + h->key.len + 1; //value存放在key后面
            h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1; //最后存放key的小写字符串

            ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
            h->key.data[h->key.len] = '\0';
            ngx_memcpy(h->value.data, r->header_start, h->value.len);
            h->value.data[h->value.len] = '\0';

            if (h->key.len == r->lowcase_index)
            {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);
            }
            else
            {
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            continue;
        }

        //返回NGX_HTTP_PARSE_HEADER_DONE表示响应中所有的http头部都解析
//完毕，接下来再接收到的都将是http包体
        if (rc == NGX_HTTP_PARSE_HEADER_DONE)
        {
            //如果之前解析http头部时没有发现server和date头部，以下会
            //根据http协议添加这两个头部
            if (r->upstream->headers_in.server == NULL)
            {
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if (h == NULL)
                {
                    return NGX_ERROR;
                }

                h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(
                                                         ngx_hash('s', 'e'), 'r'), 'v'), 'e'), 'r');

                ngx_str_set(&h->key, "Server");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char *) "server";
            }

            if (r->upstream->headers_in.date == NULL)
            {
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if (h == NULL)
                {
                    return NGX_ERROR;
                }

                h->hash = ngx_hash(ngx_hash(ngx_hash('d', 'a'), 't'), 'e');

                ngx_str_set(&h->key, "Date");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char *) "date";
            }

            return NGX_OK;
        }

        //如果返回NGX_AGAIN则表示状态机还没有解析到完整的http头部，
//要求upstream模块继续接收新的字符流再交由process_header
//回调方法解析
        if (rc == NGX_AGAIN)
        {
            return NGX_AGAIN;
        }

        //其他返回值都是非法的
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent invalid header");

        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }
}

void 
ngx_http_php_socket_tcp_close(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_http_php_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);

    for ( ;; ){
        usleep(1);

        if (ctx->enable_async == 1 || ctx->enable_thread == 0){
            break;
        }
        if (ctx->enable_upstream == 1 || ctx->enable_thread == 0){
            break;
        }
    }

    if (ctx->enable_async == 1){
        if (ctx->is_capture_multi == 0){
            ngx_http_php_subrequest_post(r);
        } else {
            ngx_http_php_subrequest_post_multi(r);
        }

        //return NGX_DONE;
    }

    if (ctx->enable_upstream == 1){
        ngx_http_php_socket_tcp(r);
        //return NGX_DONE;
    }

    pthread_join(ctx->pthread_id, NULL);

    pthread_cond_destroy(&(ctx->cond));
    pthread_mutex_destroy(&(ctx->mutex));

    //ngx_int_t rc;

    ngx_http_php_rputs_chain_list_t *chain;

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
    }

    //r->headers_out.content_type.len = sizeof("text/html") - 1;
    //r->headers_out.content_type.data = (u_char *)"text/html";
    if (!r->headers_out.status){
        r->headers_out.status = NGX_HTTP_OK;
    }

    if (r->method == NGX_HTTP_HEAD){
        rc = ngx_http_send_header(r);
        if (rc != NGX_OK){
            //return rc;
        }
    }

    if (chain != NULL){
        (*chain->last)->buf->last_buf = 1;
    }

    rc = ngx_http_send_header(r);
    if (rc != NGX_OK){
        //return rc;
    }

    ngx_http_output_filter(r, chain->out);

    ngx_http_set_ctx(r, NULL, ngx_http_php_module);

    //return NGX_OK;
}




