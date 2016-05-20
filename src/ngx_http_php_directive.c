/**
 *    Copyright(c) 2016 rryqszq4
 *
 *
 */

#include "ngx_http_php_directive.h"
#include "ngx_http_php_module.h"
#include "ngx_http_php_core.h"


char *
ngx_http_php_ini_path(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_php_main_conf_t *pmcf = conf;
	ngx_str_t *value;

	if (pmcf->ini_path.len != 0){
		return "is duplicated";
	}

	value = cf->args->elts;

	pmcf->ini_path.len = value[1].len;
	pmcf->ini_path.data = value[1].data;

	return NGX_CONF_OK;
}

char *
ngx_http_php_init_inline_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_php_main_conf_t *pmcf;
	ngx_str_t *value;
	ngx_http_php_code_t *code;

	pmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_php_module);
	if (pmcf->init_inline_code != NGX_CONF_UNSET_PTR){
		return "is duplicated";
	}

	value = cf->args->elts;

	code = ngx_http_php_code_from_string(cf->pool, &value[1]);
	if (code == NGX_CONF_UNSET_PTR){
		return NGX_CONF_ERROR;
	}
	pmcf->init_inline_code = code;

	return NGX_CONF_OK;
}

char *
ngx_http_php_init_file_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_php_main_conf_t *pmcf;
	ngx_str_t *value;
	ngx_http_php_code_t *code;

	pmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_php_module);
	if (pmcf->init_code != NGX_CONF_UNSET_PTR){
		return "is duplicated";
	}

	value = cf->args->elts;

	code = ngx_http_php_code_from_file(cf->pool, &value[1]);
	if (code == NGX_CONF_UNSET_PTR){
		return NGX_CONF_ERROR;
	}
	pmcf->init_code = code;

	return NGX_CONF_OK;
}

char *
ngx_http_php_rewrite_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_php_main_conf_t *pmcf;
	ngx_http_php_loc_conf_t *plcf;
	ngx_str_t *value;
	ngx_http_php_code_t *code;

	if (cmd->post == NULL) {
		return NGX_CONF_ERROR;
	}

	pmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_php_module);
	plcf = conf;

	if (plcf->rewrite_handler != NULL){
		return "is duplicated";
	}

	value = cf->args->elts;

	code = ngx_http_php_code_from_file(cf->pool, &value[1]);
	if (code == NGX_CONF_UNSET_PTR){
		return NGX_CONF_ERROR;
	}

	plcf->rewrite_code = code;
	plcf->rewrite_handler = cmd->post;
	pmcf->enabled_rewrite_handler = 1;

	return NGX_CONF_OK;
}

char *
ngx_http_php_rewrite_inline_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_php_main_conf_t *pmcf;
	ngx_http_php_loc_conf_t *plcf;
	ngx_str_t *value;
	ngx_http_php_code_t *code;

	if (cmd->post == NULL) {
		return NGX_CONF_ERROR;
	}

	pmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_php_module);
	plcf = conf;

	if (plcf->rewrite_handler != NULL){
		return "is duplicated";
	}

	value = cf->args->elts;

	code = ngx_http_php_code_from_string(cf->pool, &value[1]);
	if (code == NGX_CONF_UNSET_PTR){
		return NGX_CONF_ERROR;
	}

	plcf->rewrite_inline_code = code;
	plcf->rewrite_handler = cmd->post;
	pmcf->enabled_rewrite_handler = 1;

	return NGX_CONF_OK;
}

char *
ngx_http_php_access_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_php_main_conf_t *pmcf;
	ngx_http_php_loc_conf_t *plcf;
	ngx_str_t *value;
	ngx_http_php_code_t *code;

	if (cmd->post == NULL) {
		return NGX_CONF_ERROR;
	}

	pmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_php_module);
	plcf = conf;

	if (plcf->access_handler != NULL){
		return "is duplicated";
	}

	value = cf->args->elts;

	code = ngx_http_php_code_from_file(cf->pool, &value[1]);
	if (code == NGX_CONF_UNSET_PTR){
		return NGX_CONF_ERROR;
	}

	plcf->access_code = code;
	plcf->access_handler = cmd->post;
	pmcf->enabled_access_handler = 1;

	return NGX_CONF_OK;
}

char *
ngx_http_php_access_inline_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_php_main_conf_t *pmcf;
	ngx_http_php_loc_conf_t *plcf;
	ngx_str_t *value;
	ngx_http_php_code_t *code;

	if (cmd->post == NULL) {
		return NGX_CONF_ERROR;
	}

	pmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_php_module);
	plcf = conf;

	if (plcf->access_handler != NULL){
		return "is duplicated";
	}

	value = cf->args->elts;

	code = ngx_http_php_code_from_string(cf->pool, &value[1]);
	if (code == NGX_CONF_UNSET_PTR){
		return NGX_CONF_ERROR;
	}

	plcf->access_inline_code = code;
	plcf->access_handler = cmd->post;
	pmcf->enabled_access_handler = 1;

	return NGX_CONF_OK;
}

char *
ngx_http_php_content_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_php_main_conf_t *pmcf;
	ngx_http_php_loc_conf_t *plcf;
	ngx_str_t *value;
	ngx_http_php_code_t *code;

	if (cmd->post == NULL) {
		return NGX_CONF_ERROR;
	}

	pmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_php_module);
	plcf = conf;

	if (plcf->content_handler != NULL){
		return "is duplicated";
	}

	value = cf->args->elts;

	code = ngx_http_php_code_from_file(cf->pool, &value[1]);
	if (code == NGX_CONF_UNSET_PTR){
		return NGX_CONF_ERROR;
	}

	plcf->content_code = code;
	plcf->content_handler = cmd->post;
	pmcf->enabled_content_handler = 1;

	return NGX_CONF_OK;
}

char *
ngx_http_php_content_inline_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_php_main_conf_t *pmcf;
	ngx_http_php_loc_conf_t *plcf;
	ngx_str_t *value;
	ngx_http_php_code_t *code;

	if (cmd->post == NULL) {
		return NGX_CONF_ERROR;
	}

	pmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_php_module);
	plcf = conf;

	if (plcf->content_handler != NULL){
		return "is duplicated";
	}

	value = cf->args->elts;

	code = ngx_http_php_code_from_string(cf->pool, &value[1]);
	if (code == NGX_CONF_UNSET_PTR){
		return NGX_CONF_ERROR;
	}

	plcf->content_inline_code = code;
	plcf->content_handler = cmd->post;
	pmcf->enabled_content_handler = 1;

	return NGX_CONF_OK;
}


#if defined(NDK) && NDK

char *
ngx_http_php_set_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_str_t *value;
	ngx_str_t target;
	ndk_set_var_t filter;

	ngx_http_php_set_var_data_t *filter_data;

	/*
		value[0] = "php_set_code"
		value[1] = target variable name
		value[2] = php code
		value[3..] = real params
	*/

	value = cf->args->elts;
	target = value[1];

	filter.type = NDK_SET_VAR_MULTI_VALUE_DATA;
	filter.func = cmd->post;
	filter.size = cf->args->nelts - 3;

	filter_data = ngx_palloc(cf->pool, sizeof(ngx_http_php_set_var_data_t));
	if (filter_data == NULL){
		return NGX_CONF_ERROR;
	}

	filter_data->size = filter.size;
	filter_data->script = value[2];

	filter_data->code = ngx_http_php_code_from_string(cf->pool, &filter_data->script);
	if (filter_data->code == NGX_CONF_UNSET_PTR){
		return NGX_CONF_ERROR;
	}

	filter.data = filter_data;

	PHP_EMBED_START_BLOCK(0, NULL);
		zval retval;
		zend_eval_string_ex(filter_data->code->code.string, &retval, "ngx_php run code return", 1 TSRMLS_CC);

		if (Z_TYPE(retval) == IS_NULL){
			filter_data->result.data = NULL;
			filter_data->result.len = 0;
		}else {
			convert_to_string(&retval);

			filter_data->result.data = ngx_palloc(cf->pool, Z_STRLEN(retval));
			ngx_memcpy(filter_data->result.data, Z_STRVAL(retval), Z_STRLEN(retval));
			filter_data->result.len = Z_STRLEN(retval);
		}

		zval_dtor(&retval);
	PHP_EMBED_END_BLOCK();
	
	return ndk_set_var_multi_value_core(cf, &target, &value[3], &filter);
}

char *
ngx_http_php_set_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
	ngx_str_t *value;
	ngx_str_t target;
	ndk_set_var_t filter;

	ngx_http_php_set_var_data_t *filter_data;

	/*
		value[0] = "php_set_inline"
		value[1] = target variable name
		value[2] = php code
		value[3..] = real params
	*/

	value = cf->args->elts;
	target = value[1];

	filter.type = NDK_SET_VAR_MULTI_VALUE_DATA;
	filter.func = cmd->post;
	filter.size = cf->args->nelts - 3;

	filter_data = ngx_palloc(cf->pool, sizeof(ngx_http_php_set_var_data_t));
	if (filter_data == NULL){
		return NGX_CONF_ERROR;
	}

	filter_data->size = filter.size;
	filter_data->script = value[2];

	filter_data->code = ngx_http_php_code_from_file(cf->pool, &filter_data->script);
	if (filter_data->code == NGX_CONF_UNSET_PTR){
		return NGX_CONF_ERROR;
	}

	filter.data = filter_data;

	return ndk_set_var_multi_value_core(cf, &target, &value[3], &filter);
}

#endif











