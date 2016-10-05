/**
 *    Copyright(c) 2016 rryqszq4
 *
 *
 */

#include "php_ngx_log.h"

static zend_class_entry *php_ngx_log_class_entry;

ZEND_BEGIN_ARG_INFO_EX(ngx_log_log_arginfo, 0, 0, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(ngx_log, log)
{
    
}

static const zend_function_entry php_ngx_log_class_functions[] = {
    PHP_ME(ngx_log, log, ngx_log_log_arginfo, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    {NULL, NULL, NULL, 0, 0}
};

void 
ngx_log_init(int module_number TSRMLS_DC)
{
    zend_class_entry ngx_log_class_entry;
    INIT_CLASS_ENTRY(ngx_log_class_entry, "ngx_log", php_ngx_log_class_functions);
    php_ngx_log_class_entry = zend_register_internal_class(&ngx_log_class_entry TSRMLS_CC);
}