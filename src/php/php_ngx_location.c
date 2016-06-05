/**
 *    Copyright(c) 2016 rryqszq4
 *
 *
 */

#include "php_ngx_location.h"
#include "../ngx_http_php_module.h"
#include "../ngx_http_php_request.h"
#include "../ngx_http_php_subrequest.h"

static zend_class_entry *php_ngx_location_class_entry;

ZEND_BEGIN_ARG_INFO_EX(arginfo_ngx_location_construct, 0, 0, 0)
ZEND_END_ARG_INFO()
ZEND_BEGIN_ARG_INFO_EX(arginfo_ngx_location_capture_async, 0, 0, 2)
    ZEND_ARG_INFO(0, uri)
    ZEND_ARG_INFO(0, closure)
ZEND_END_ARG_INFO()
ZEND_BEGIN_ARG_INFO_EX(arginfo_ngx_location_capture_multi_async, 0, 0, 1)
    ZEND_ARG_INFO(0, str)
ZEND_END_ARG_INFO()

PHP_METHOD(ngx_location, capture_async)
{
	char *uri_str, *name_str, *lcname, *tmp;
	int uri_len, name_len, tmp_len;

	zval *closure = NULL;
	zval *classname;

	zend_class_entry **pce;
	zend_class_entry *ce;
	zend_function *fptr;

	zval *val;

	if (zend_parse_parameters_ex(ZEND_PARSE_PARAMS_QUIET, ZEND_NUM_ARGS() TSRMLS_CC, "sO", &uri_str, &uri_len, &closure, zend_ce_closure) == SUCCESS) {
    	fptr = (zend_function*)zend_get_closure_method_def(closure TSRMLS_CC);
    	Z_ADDREF_P(closure);
  	} else if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &uri_str, &uri_len, &name_str, &name_len) == SUCCESS) {
		if ((tmp = strstr(name_str, "::")) == NULL) {
			char *nsname;

			lcname = zend_str_tolower_dup(name_str, name_len);

			// Ignore leading "\" 
			nsname = lcname;
			if (lcname[0] == '\\') {
			nsname = &lcname[1];
			name_len--;
			}

			if (zend_hash_find(EG(function_table), nsname, name_len + 1, (void **)&fptr) == FAILURE) {
				efree(lcname);
				php_error_docref(NULL TSRMLS_CC, E_WARNING, 
		    	"Function %s() does not exist", name_str);
		   		return;
			}
			efree(lcname);
		}else {
			tmp_len = tmp - name_str;
			MAKE_STD_ZVAL(classname);
			ZVAL_STRINGL(classname, name_str, tmp_len, 1);
			name_len = name_len - (tmp_len + 2);
			name_str = tmp + 2;
			//php_printf("classname: %s, method: %s\n", Z_STRVAL_P(classname), name_str);
			if (zend_lookup_class(Z_STRVAL_P(classname), Z_STRLEN_P(classname), &pce TSRMLS_CC) == FAILURE) {
				php_error_docref(NULL TSRMLS_CC, E_WARNING,
				"Class %s does exist", Z_STRVAL_P(classname));
				//zend_throw_exception_ex(reflection_exception_ptr, 0 TSRMLS_CC,
				//    "Class %s does not exist", Z_STRVAL_P(classname)); 
				zval_dtor(classname);
				return;
			}
			ce = *pce;

			lcname = zend_str_tolower_dup(name_str, name_len);

			if (zend_hash_find(&ce->function_table, lcname, name_len + 1, (void **) &fptr) == FAILURE) {
				efree(lcname);
				php_error_docref(NULL TSRMLS_CC, E_WARNING,
				"Method %s::%s() does not exist", ce->name, name_str);
				//zend_throw_exception_ex(reflection_exception_ptr, 0 TSRMLS_CC, 
				//  "Method %s::%s() does not exist", ce->name, name_str);
				return;
			}
		  	efree(lcname);
		}
	}else {
    	return ;
	}

	MAKE_STD_ZVAL(val);

#if PHP_VERSION_ID < 50399
	zend_create_closure(val, fptr TSRMLS_CC);
#else
	zend_create_closure(val, fptr, NULL, NULL TSRMLS_CC);
#endif

	/*if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &str, &str_len) == FAILURE)
	{
		return ;
	}*/

	ngx_http_php_request_context_t *context = (ngx_http_php_request_context_t *)SG(server_context);
	ngx_http_request_t *r = (ngx_http_request_t *)context->r;

	ngx_http_php_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);

	if (ctx == NULL){
		
	}

	ctx->capture_uri.data = (u_char *)uri_str;
	ctx->capture_uri.len = uri_len;

	ctx->closure = val;

	ngx_http_php_subrequest_post(r);

	return ;
}

PHP_METHOD(ngx_location, capture_multi_async)
{
	char *uri_str;
	int uri_len;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &uri_str, &uri_len) == FAILURE)
	{
		return ;
	}

	ngx_http_php_request_context_t *context = (ngx_http_php_request_context_t *)SG(server_context);
	ngx_http_request_t *r = (ngx_http_request_t *)context->r;

	ngx_http_php_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);

	if (ctx == NULL){
		
	}

	ctx->capture_uri.data = (u_char *)uri_str;
	ctx->capture_uri.len = uri_len;

	ngx_http_php_subrequest_post(r);

	return ;
}

static const zend_function_entry php_ngx_location_class_functions[] = {
	PHP_ME(ngx_location, capture_async, arginfo_ngx_location_capture_async, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
	PHP_ME(ngx_location, capture_multi_async, arginfo_ngx_location_capture_multi_async, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
	{NULL, NULL, NULL, 0, 0}
};

void 
ngx_location_init(int module_number TSRMLS_DC)
{
	zend_class_entry ngx_location_class_entry;
	INIT_CLASS_ENTRY(ngx_location_class_entry, "ngx_location", php_ngx_location_class_functions);
	php_ngx_location_class_entry = zend_register_internal_class(&ngx_location_class_entry TSRMLS_CC);
}