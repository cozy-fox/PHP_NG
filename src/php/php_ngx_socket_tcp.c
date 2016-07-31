/**
 *    Copyright(c) 2016 rryqszq4
 *
 *
 */

#include "php_ngx_socket_tcp.h"

ZEND_BEGIN_ARG_INFO_EX(ngx_socket_tcp_construct_arginfo, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ngx_socket_tcp_connect_arginfo, 0, 0, 3)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ngx_socket_tcp_send_arginfo, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ngx_socket_tcp_receive_arginfo, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ngx_socket_tcp_close_arginfo, 0, 0, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(ngx_socket_tcp, __construct)
{

}

PHP_METHOD(ngx_socket_tcp, connect)
{
    char *host_str;
    int host_len, port;
    zval *options = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|la", &host_str, &host_len, &options) == FAILURE)
    {
        RETURN_NULL();
    }
}

PHP_METHOD(ngx_socket_tcp, send)
{

}

PHP_METHOD(ngx_socket_tcp, receive)
{

}

PHP_METHOD(ngx_socket_tcp, close)
{
    
}

static const zend_function_entry php_ngx_socket_tcp_class_functions[] = {
    PHP_ME(ngx_socket_tcp, __construct, ngx_socket_tcp_construct_arginfo, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(ngx_socket_tcp, connect, ngx_socket_tcp_connect_arginfo, ZEND_ACC_PUBLIC)
    PHP_ME(ngx_socket_tcp, send, ngx_socket_tcp_send_arginfo, ZEND_ACC_PUBLIC)
    PHP_ME(ngx_socket_tcp, receive, ngx_socket_tcp_receive_arginfo, ZEND_ACC_PUBLIC)
    PHP_ME(ngx_socket_tcp, close, ngx_socket_tcp_close_arginfo, ZEND_ACC_PUBLIC)
    {NULL, NULL, NULL, 0, 0}
};

void 
php_ngx_socket_tcp_init(int module_number TSRMLS_DC)
{
    zend_class_entry ngx_socket_tcp_class_entry;
    INIT_CLASS_ENTRY(ngx_socket_tcp_class_entry, "ngx_socket_tcp", php_ngx_socket_tcp_class_functions);
    php_ngx_socket_tcp_class_entry = zend_register_internal_class(&ngx_socket_tcp_class_entry TSRMLS_CC);
}