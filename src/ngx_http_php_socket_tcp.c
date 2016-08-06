/**
 *    Copyright(c) 2016 rryqszq4
 *
 *
 */

#include "ngx_http_php_socket_tcp.h"

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
    if (pHost = NULL){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "gethostbyname fail. %s", strerror(errno));
        return NGX_ERROR;
    }

    backendSockAddr.sin_family = AF_INET;
    backendSockAddr.sin_port = htons((in_por_t) ctx->port);

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

}

ngx_int_t 
ngx_http_php_socket_tcp_close(ngx_http_request_t *r)
{

}




