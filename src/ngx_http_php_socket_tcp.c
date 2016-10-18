/**
 *    Copyright(c) 2016 rryqszq4
 *
 *
 */

#include "ngx_http_php_socket_tcp.h"
#include "ngx_http_php_subrequest.h"

ngx_int_t 
ngx_http_php_socket_tcp_run(ngx_http_request_t *r)
{
    ngx_php_request = r;
    //ngx_str_t *host;
    int port;
    ngx_url_t url;

    ngx_http_php_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_http_php_module);

    ngx_http_php_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);

    if (ctx == NULL){
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_php_upstream_create(r) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_upstream_create() failed");
        return NGX_ERROR;
    }

    ngx_http_upstream_t *u = r->upstream;

    u->conf = &plcf->upstream;

    u->buffering = plcf->upstream.buffering;

    port = ctx->port;

    ngx_memzero(&url, sizeof(ngx_url_t));
    url.url.len = ctx->host.len;
    url.url.data = ctx->host.data;
    url.default_port = (in_port_t) port;
    url.no_resolve = 1;

    if (ngx_parse_url(r->pool, &url) != NGX_OK) {
        if (url.err) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "%s in upstream \"%V\"", url.err, &url.url);
        }
        return NGX_ERROR;
    }

    u->resolved = (ngx_http_upstream_resolved_t *)ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if (u->resolved == NULL){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_pcalloc resolved error. %s.", strerror(errno));
        return NGX_ERROR;
    }

    /*host = ngx_palloc(r->pool, ctx->host.len);
    ngx_cpystrn((u_char *)host, ctx->host.data, ctx->host.len + 1);

    static struct sockaddr_in addr;
    //bzero(&addr, sizeof(addr));
    
    struct hostent *pHost = gethostbyname((char*)"cha.17173.com");
    
    if (pHost == NULL){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "gethostbyname fail. %s", strerror(errno));
        return NGX_ERROR;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons((in_port_t) 80);

    char* pDmsIP = inet_ntoa(*(struct in_addr*) (pHost->h_addr_list[0]));
    //char* pDmsIP = inet_ntoa(*(struct in_addr*) ("10.10.0.2"));
    addr.sin_addr.s_addr = inet_addr(pDmsIP);
    //202.108.37.102
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s", pDmsIP);

    u->resolved->sockaddr = (struct sockaddr *)&addr;
    u->resolved->socklen = sizeof(struct sockaddr_in);
    u->resolved->naddrs = 1;*/

    if (url.addrs && url.addrs[0].sockaddr) {
        u->resolved->sockaddr = url.addrs[0].sockaddr;
        u->resolved->socklen = url.addrs[0].socklen;
        u->resolved->naddrs = 1;
        u->resolved->host = url.addrs[0].name;

    } else {
        u->resolved->host = url.host;
        u->resolved->port = (in_port_t) (url.no_port ? port : url.port);
        u->resolved->no_port = url.no_port;
    }

    u->create_request = ngx_http_php_socket_tcp_create_request;
    u->reinit_request = ngx_http_php_socket_tcp_reinit_request;
    u->process_header = ngx_http_php_socket_tcp_process_header;
    u->abort_request = ngx_http_php_socket_tcp_abort_request;
    u->finalize_request = ngx_http_php_socket_tcp_finalize_request;

    ctx->request = r;

    u->input_filter_init = ngx_http_php_socket_tcp_filter_init;
    u->input_filter = ngx_http_php_socket_tcp_filter;
    u->input_filter_ctx = ctx;

    r->subrequest_in_memory = 1;

    r->main->count++;

    //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_php_upstream_init");

    ngx_http_php_upstream_init(r);

    ngx_http_set_ctx(r, ctx, ngx_http_php_module);

    //if (ctx->read_or_write == 0) {
        /*u->create_request(r);
        u->request_sent = 0;

        ngx_connection_t  *c;
        c = u->peer.connection;
        ngx_add_timer(c->write, u->conf->send_timeout);*/
        //ngx_http_php_upstream_send_request(r, u);
    /*}else if (ctx->read_or_write == 1) {

        //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_php_upstream_process_header");

        ngx_connection_t  *c;
        c = u->peer.connection;

        if (c->write->timer_set) {
            ngx_del_timer(c->write);
        }

        ngx_add_timer(c->read, u->conf->read_timeout);

        if (c->read->ready) {
            ngx_http_php_upstream_process_header(r, u);
        }
    }*/

    return NGX_OK;
}

ngx_int_t 
ngx_http_php_socket_tcp_create_request(ngx_http_request_t *r)
{
    ngx_buf_t  *b;
    ngx_chain_t *cl;

    ngx_php_request = r;
    ngx_http_php_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);

    if (ctx->send_buf.data) {
        b = ngx_create_temp_buf(r->pool, ctx->send_buf.len+1);
        if (b == NULL) {
            return NGX_ERROR;
        }
        
        cl = ngx_alloc_chain_link(r->pool);

        cl->buf = b;
        cl->next = NULL;

        r->upstream->request_bufs = cl;

        b->last = ngx_copy(b->last, ctx->send_buf.data, ctx->send_buf.len);

        /*
        b->last = b->pos + ctx->send_buf.len;

        ngx_snprintf(b->pos, ctx->send_buf.len, (char*)ctx->send_buf.data); 
                  
        r->upstream->request_bufs = ngx_alloc_chain_link(r->pool);
        if (r->upstream->request_bufs == NULL) {
            return NGX_ERROR;
        }

        r->upstream->request_bufs->buf = b;
        r->upstream->request_bufs->next = NULL;
        */

        /*r->upstream->request_sent = 0;
        r->upstream->header_sent = 0;

        r->header_hash = 1;
        */
        //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
        //                  "start %s %d", r->upstream->request_bufs->buf->last, ctx->send_buf.len);

        ngx_http_set_ctx(r, ctx, ngx_http_php_module);
    }
    return NGX_OK;
}

ngx_int_t 
ngx_http_php_socket_tcp_reinit_request(ngx_http_request_t *r)
{
    return NGX_OK;
}

ngx_int_t 
ngx_http_php_socket_tcp_process_header(ngx_http_request_t *r)
{
    ngx_php_request = r;

    //size_t len;
    //ngx_int_t rc;
    ngx_http_upstream_t *u;

    ngx_http_php_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);
    if (ctx == NULL){
        return NGX_ERROR;
    }

    u = r->upstream;

    //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%*s", (&u->buffer)->last - (&u->buffer)->pos,(&u->buffer)->pos);

    ctx->receive_buf.len = (&u->buffer)->last - (&u->buffer)->pos;
    ctx->receive_buf.data = (&u->buffer)->pos;

    //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "recv=%*s,len=%d", ctx->receive_buf.len, ctx->receive_buf.data, ctx->receive_buf.len);

    ctx->enable_upstream = 0;
    ngx_http_set_ctx(r, ctx, ngx_http_php_module);

    pthread_mutex_lock(&(ctx->mutex));
    pthread_cond_signal(&(ctx->cond));
    pthread_mutex_unlock(&(ctx->mutex));

    /*rc = ngx_http_parse_status_line(r, &u->buffer, &ctx->receive_status);

    if (rc == NGX_AGAIN){
        return rc;
    }*/

    if (u->state)
    {
        u->state->status = 200;
    }

    u->headers_in.status_n = 200;

    /*len = ctx->receive_status.end - ctx->receive_status.start;
    u->headers_in.status_line.len = len;

    u->headers_in.status_line.data = ngx_pnalloc(r->pool, len);
    if (u->headers_in.status_line.data == NULL)
    {
        return NGX_ERROR;
    }

    ngx_memcpy(u->headers_in.status_line.data, ctx->receive_status.start, len);

    u->process_header = ngx_http_php_socket_tcp_receive_parse;

    return ngx_http_php_socket_tcp_receive_parse(r);*/

    return NGX_OK;

}

void 
ngx_http_php_socket_tcp_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ngx_http_php_socket_tcp abort_request");
    return;
}

void 
ngx_http_php_socket_tcp_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ngx_http_php_socket_tcp finalize_request");

    ngx_http_php_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);
    
    if (rc == 0){
        ngx_http_php_socket_tcp_handler(r);
    } else {
        pthread_cancel(ctx->pthread_id);

        pthread_cond_destroy(&(ctx->cond));
        pthread_mutex_destroy(&(ctx->mutex));
    }

    return ;
}

ngx_int_t 
ngx_http_php_socket_tcp_filter_init(void *data)
{
    ngx_http_php_ctx_t *ctx = data;

    ngx_http_request_t *r;
    ngx_http_upstream_t *u;

    r = ctx->request;
    u = r->upstream;

    //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%d", u->headers_in.status_n);

    if (u->headers_in.status_n != 404){

    }else {
        u->length = 0;
    }

    return NGX_OK;
}

ngx_int_t 
ngx_http_php_socket_tcp_filter(void *data, ssize_t bytes)
{
    /*ngx_http_php_ctx_t *ctx = data;

    ngx_http_request_t *r;
    ngx_http_upstream_t *u;

    r = ctx->request;
    u = ctx->request->upstream;

    ngx_http_php_rputs_chain_list_t *chain;

    chain = ctx->rputs_chain;

    if (ctx->rputs_chain == NULL){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%d", bytes);
    }else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s", (*chain->last)->buf->pos);
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "input_filter");*/

    //return NGX_OK;

    ngx_http_php_ctx_t *ctx = data;

    ngx_http_request_t *r;
    r = ctx->request;

    return ngx_http_php_socket_tcp_rediscovery(r);
}

ngx_int_t
ngx_http_php_socket_tcp_rediscovery(ngx_http_request_t *r)
{
    ngx_php_request = r;

    ngx_http_php_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);

    ngx_http_upstream_t *u;

    u = ctx->request->upstream;

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

        return NGX_DONE;
    }

    //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%d", ctx->enable_upstream);

    if (ctx->enable_upstream == 1){
        //if (ctx->read_or_write == 0) {
            ngx_http_php_socket_tcp_create_request(r);
            u->request_sent = 0;

            ngx_connection_t  *c;
            c = u->peer.connection;
            ngx_add_timer(c->write, u->conf->send_timeout);
            
            ngx_http_php_upstream_send_request(r, u);
        /*}else if (ctx->read_or_write == 1) {

            ngx_connection_t  *c;
            c = u->peer.connection;

            if (c->write->timer_set) {
                ngx_del_timer(c->write);
            }

            ngx_add_timer(c->read, u->conf->read_timeout);

            if (c->read->ready) {
                ngx_http_php_upstream_process_header(r, u);
            }
        }*/

        return NGX_DONE;

    }

    pthread_join(ctx->pthread_id, NULL);

    pthread_cond_destroy(&(ctx->cond));
    pthread_mutex_destroy(&(ctx->mutex));

    return NGX_OK;
}

ngx_int_t
ngx_http_php_socket_tcp_handler(ngx_http_request_t *r)
{
    ngx_php_request = r;

    ngx_http_php_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);

    /*ngx_http_upstream_t *u;

    u = ctx->request->upstream;

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

        return NGX_DONE;
    }

    if (ctx->enable_upstream == 1){
        ngx_http_php_socket_tcp_create_request(r);
        u->request_sent = 0;

        ngx_connection_t  *c;
        c = u->peer.connection;
        ngx_add_timer(c->write, u->conf->send_timeout);
        
        ngx_http_php_upstream_send_request(r, u);
        return NGX_DONE;
    }

    pthread_join(ctx->pthread_id, NULL);

    pthread_cond_destroy(&(ctx->cond));
    pthread_mutex_destroy(&(ctx->mutex));*/

    ngx_int_t rc;

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




