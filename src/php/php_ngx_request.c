/**
 *    Copyright(c) 2016-2017 rryqszq4
 *
 *
 */

#include "php_ngx_log.h"
#include "../ngx_http_php_module.h"

static zend_class_entry *php_ngx_request_class_entry;

static const zend_function_entry php_ngx_request_class_functions[] = {
    {NULL, NULL, NULL, 0, 0}
};

void php_ngx_request_init(int module_number TSRMLS_DC)
{
    zend_class_entry ngx_request_class_entry;
    INIT_CLASS_ENTRY(ngx_request_class_entry, "ngx_request", php_ngx_request_class_functions);
    php_ngx_request_class_entry = zend_register_internal_class(&ngx_request_class_entry TSRMLS_CC);
}