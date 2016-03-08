/**
 *    Copyright(c) 2016 rryqszq4
 *
 *
 */

 #include "ngx_http_php_directive.h"
 #include "ngx_http_php_module.h"
 #include "ngx_http_php_core.h"

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
 	//pmcf->enabled_content_handler = 1;

 	return NGX_CONF_OK;
 }











