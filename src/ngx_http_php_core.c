/**
 *    Copyright(c) 2016 rryqszq4
 *
 *
 */

#include "ngx_http_php_module.h"
#include "ngx_http_php_core.h"

#include <php_embed.h>

ngx_http_php_code_t *
ngx_http_php_code_from_string(ngx_pool_t *pool, ngx_str_t *code_str)
{
	ngx_http_php_code_t *code;
	size_t len;

	code = ngx_pcalloc(pool, sizeof(*code));
	if (code == NULL){
		return NGX_CONF_UNSET_PTR;
	}

	len = ngx_strlen(code_str->data);
	code->code.string = ngx_pcalloc(pool, len + 1);
	if (code->code.string == NULL){
		return NGX_CONF_UNSET_PTR;
	}
	ngx_cpystrn((u_char *)code->code.string, code_str->data, len + 1);
	code->code_type = NGX_HTTP_PHP_CODE_TYPE_STRING;
	return code;
}
