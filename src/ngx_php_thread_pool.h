/**
 *    Copyright(c) 2016-2017 rryqszq4
 *
 *
 */

#ifndef _NGX_PHP_THREAD_POOL_H_
#define _NGX_PHP_THREAD_POOL_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

typedef struct ngx_php_thread_task_s ngx_php_thread_task_t;

struct ngx_php_thread_task_s {
    ngx_php_thread_task_t   *next;
    ngx_uint_t              id;
    void                    *ctx;
    void                    (*handler)(void *data, ngx_log_t *log);
    ngx_event_t             event;
};

typedef struct ngx_php_thread_pool_s ngx_php_thread_pool_t;

ngx_php_thread_pool_t *ngx_php_thread_pool_add(ngx_conf_t *cf, ngx_str_t *name);
ngx_php_thread_pool_t *ngx_php_thread_pool_get(ngx_cycle_t *cycle, ngx_str_t *name);

ngx_php_thread_task_t *ngx_php_thread_task_alloc(ngx_pool_t *pool, size_t size);
ngx_int_t ngx_php_thread_task_post(ngx_php_thread_pool_t *tp, ngx_php_thread_task_t *task);

#endif