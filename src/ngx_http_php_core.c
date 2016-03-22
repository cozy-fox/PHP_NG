/**
 *    Copyright(c) 2016 rryqszq4
 *
 *
 */

#include "ngx_http_php_module.h"
#include "ngx_http_php_request.h"
#include "ngx_http_php_core.h"

ngx_http_php_code_t *
ngx_http_php_code_from_file(ngx_pool_t *pool, ngx_str_t *code_file_path)
{
	ngx_http_php_code_t *code;
	size_t len;
	u_char *p;

	code = ngx_pcalloc(pool, sizeof(*code));
	if (code == NULL){
		return NGX_CONF_UNSET_PTR;
	}

	len = ngx_strlen((char *)code_file_path->data);
	if (len == 0){
		return NGX_CONF_UNSET_PTR;
	}else if (code_file_path->data[0] == '/'){
		code->code.file = ngx_pcalloc(pool, len + 1);
		if (code->code.file == NULL){
			return NGX_CONF_UNSET_PTR;
		}
		ngx_cpystrn((u_char *)code->code.file, (u_char *)code_file_path->data, code_file_path->len + 1);	
	}else {
		code->code.file = ngx_pcalloc(pool, ngx_cycle->conf_prefix.len + len + 1);
		if (code->code.file == NULL){
			return NGX_CONF_UNSET_PTR;
		}
		p = ngx_cpystrn((u_char *)code->code.file, (u_char *)ngx_cycle->conf_prefix.data, ngx_cycle->conf_prefix.len + 1);
		ngx_cpystrn(p, (u_char *)code_file_path->data, code_file_path->len + 1);
	}
	code->code_type = NGX_HTTP_PHP_CODE_TYPE_FILE;
	return code;
}

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


int ngx_http_php_code_ub_write(const char *str, unsigned int str_length TSRMLS_DC)
{
	ngx_buf_t *b;
	ngx_http_php_rputs_chain_list_t *chain;
	ngx_http_php_ctx_t *ctx;
	ngx_http_request_t *r;
	u_char *u_str;
	ngx_str_t ns;

	r = ngx_php_request;
	ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);

	ns.data = (u_char *)str;
	ns.len = str_length;

	if (ctx->rputs_chain == NULL){
		chain = ngx_pcalloc(r->pool, sizeof(ngx_http_php_rputs_chain_list_t));
		chain->out = ngx_alloc_chain_link(r->pool);
		chain->last = &chain->out;
	}else {
		chain = ctx->rputs_chain;
		(*chain->last)->next = ngx_alloc_chain_link(r->pool);
		chain->last = &(*chain->last)->next;
	}

	b = ngx_calloc_buf(r->pool);
	(*chain->last)->buf = b;
	(*chain->last)->next = NULL;

	u_str = ngx_pstrdup(r->pool, &ns);
	u_str[ns.len] = '\0';
	(*chain->last)->buf->pos = u_str;
	(*chain->last)->buf->last = u_str + ns.len;
	(*chain->last)->buf->memory = 1;
	ctx->rputs_chain = chain;
	ngx_http_set_ctx(r, ctx, ngx_http_php_module);

	if (r->headers_out.content_length_n == -1){
		r->headers_out.content_length_n += ns.len + 1;
	}else {
		r->headers_out.content_length_n += ns.len;
	}

	return r->headers_out.content_length_n;
}

void 
ngx_http_php_code_flush(void *server_context)
{
	
}

void ngx_http_php_code_log_message(char *message)
{
	

}

void ngx_http_php_code_register_server_variables(zval *track_vars_array TSRMLS_DC)
{
	php_import_environment_variables(track_vars_array TSRMLS_CC);

	ngx_http_request_t *r;
	r = ngx_php_request;

	ngx_http_headers_in_t *headers_in;
	headers_in = &r->headers_in;

	ngx_list_part_t *part = &r->headers_in.headers.part;
	ngx_table_elt_t *header = part->elts;

	ngx_uint_t i;

	if (r->method == NGX_HTTP_GET){
		php_register_variable("REQUEST_METHOD", (char *)"GET", track_vars_array TSRMLS_CC);
	} else if (r->method == NGX_HTTP_POST){
		php_register_variable("REQUEST_METHOD", (char *)"POST", track_vars_array TSRMLS_CC);
	}

	//php_register_variable_safe("REQUEST_LINE", (char *)r->request_line.data, r->request_line.len, track_vars_array TSRMLS_CC);

	php_register_variable_safe("DOCUMENT_URI", (char *)r->uri.data, r->uri.len, track_vars_array TSRMLS_CC);

	if (r->args.len > 0){
		php_register_variable_safe("QUERY_STRING", (char *)r->args.data, r->args.len, track_vars_array TSRMLS_CC);
	}

	php_register_variable_safe("REQUEST_URI", (char *)r->uri_start, strlen((char *)r->uri_start)-strlen((char *)r->uri_end),track_vars_array TSRMLS_CC);
	
	php_register_variable_safe("SERVER_PROTOCOL", (char *)r->http_protocol.data, r->http_protocol.len, track_vars_array TSRMLS_CC);

	php_register_variable_safe("REMOTE_ADDR", (char *)r->connection->addr_text.data, r->connection->addr_text.len, track_vars_array TSRMLS_CC);

	ngx_str_t  server_address;
    u_char     server_addr[NGX_SOCKADDR_STRLEN];
    server_address.len = NGX_SOCKADDR_STRLEN;
    server_address.data = server_addr;
    if (ngx_connection_local_sockaddr(r->connection, &server_address, 0) != NGX_OK) {
    }
    php_register_variable_safe("SERVER_ADDR", (char *)server_address.data, server_address.len, track_vars_array TSRMLS_CC);

	ngx_uint_t port;
    struct sockaddr_in	*sin;
    char *tmp_port;
    tmp_port = emalloc(sizeof("65535") - 1);
	sin = (struct sockaddr_in *) r->connection->local_sockaddr;
    port = ntohs(sin->sin_port);
    ngx_sprintf((u_char *)tmp_port, "%ui", port);
    php_register_variable("SERVER_PORT", (char *)tmp_port, track_vars_array TSRMLS_CC);
	efree(tmp_port);

    tmp_port = emalloc(sizeof("65535") - 1);
    sin = (struct sockaddr_in *) r->connection->sockaddr;
    port = ntohs(sin->sin_port);
    ngx_sprintf((u_char *)tmp_port, "%ui", port);
	php_register_variable("REMOTE_PORT", (char *)tmp_port, track_vars_array TSRMLS_CC);
	efree(tmp_port);
	
	ngx_http_core_srv_conf_t  *cscf;
    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
    php_register_variable_safe("SERVER_NAME", (char *)cscf->server_name.data, cscf->server_name.len, track_vars_array TSRMLS_CC);


	for (i = 0; /* void */; i++){
		if (i >= part->nelts){
			if (part->next == NULL){
				break;
			}
			part = part->next;
			header = part->elts;
			i = 0;
		}

		if (ngx_strncasecmp(header[i].lowcase_key, (u_char *)"accept", header[i].key.len) == 0){
			php_register_variable_safe("HTTP_ACCEPT", (char *)header[i].value.data, header[i].value.len, track_vars_array TSRMLS_CC);
		}

		if (ngx_strncasecmp(header[i].lowcase_key, (u_char *)"host", header[i].key.len) == 0){
			php_register_variable_safe("HTTP_HOST", (char *)header[i].value.data, header[i].value.len, track_vars_array TSRMLS_CC);
		}

		if (ngx_strncasecmp(header[i].lowcase_key, (u_char *)"connection", header[i].key.len) == 0){
			php_register_variable_safe("HTTP_CONNECTION", (char *)header[i].value.data, header[i].value.len, track_vars_array TSRMLS_CC);
		}

		if (ngx_strncasecmp(header[i].lowcase_key, (u_char *)"user-agent", header[i].key.len) == 0){
			php_register_variable_safe("HTTP_USER_AGENT", (char *)header[i].value.data, header[i].value.len, track_vars_array TSRMLS_CC);
		}

		if (ngx_strncasecmp(header[i].lowcase_key, (u_char *)"accept-encoding", header[i].key.len) == 0){
			php_register_variable_safe("HTTP_ACCEPT_ENCODING", (char *)header[i].value.data, header[i].value.len, track_vars_array TSRMLS_CC);
		}

		if (ngx_strncasecmp(header[i].lowcase_key, (u_char *)"accept-language", header[i].key.len) == 0){
			php_register_variable_safe("HTTP_ACCEPT_LANGUAGE", (char *)header[i].value.data, header[i].value.len, track_vars_array TSRMLS_CC);
		}
		
		if (ngx_strncasecmp(header[i].lowcase_key, (u_char *)"referer", header[i].key.len) == 0){
			php_register_variable_safe("HTTP_REFERER", (char *)header[i].value.data, header[i].value.len, track_vars_array TSRMLS_CC);
		}

		if (ngx_strncasecmp(header[i].lowcase_key, (u_char *)"pragma", header[i].key.len) == 0){
			php_register_variable_safe("HTTP_PRAGMA", (char *)header[i].value.data, header[i].value.len, track_vars_array TSRMLS_CC);
		}

		if (ngx_strncasecmp(header[i].lowcase_key, (u_char *)"cache-control", header[i].key.len) == 0){
			php_register_variable_safe("HTTP_CACHE_CONTROL", (char *)header[i].value.data, header[i].value.len, track_vars_array TSRMLS_CC);
		}

		if (ngx_strncasecmp(header[i].lowcase_key, (u_char *)"upgrade-insecure-requests", header[i].key.len) == 0){
			php_register_variable_safe("HTTP_UPGRADE_INSECURE_REQUESTS", (char *)header[i].value.data, header[i].value.len, track_vars_array TSRMLS_CC);
		}

	}

}

ngx_int_t 
ngx_php_embed_run(ngx_http_request_t *r, ngx_http_php_code_t *code)
{

	php_embed_module.ub_write = ngx_http_php_code_ub_write;
	php_embed_module.flush = ngx_http_php_code_flush;
	php_embed_module.php_ini_path_override = "/usr/local/php/etc/php.ini";
	PHP_EMBED_START_BLOCK(0, NULL);
		zend_eval_string_ex(code->code.string, NULL, "php_ngx run code", 1 TSRMLS_CC);
	PHP_EMBED_END_BLOCK();

	return 0;
}

ngx_int_t
ngx_php_ngx_run(ngx_http_request_t *r, ngx_http_php_code_t *code)
{

	ngx_http_php_request_init(r TSRMLS_CC);

	php_ngx_request_init(TSRMLS_C);

	zend_first_try {

		if (code->code_type == NGX_HTTP_PHP_CODE_TYPE_STRING){

			zend_eval_string_ex(code->code.string, NULL, "php_ngx run code", 1 TSRMLS_CC);

		}else if (code->code_type == NGX_HTTP_PHP_CODE_TYPE_FILE){

			zend_file_handle file_handle;

			file_handle.type = ZEND_HANDLE_FP;
			file_handle.opened_path = NULL;
			file_handle.free_filename = 0;
			file_handle.filename = code->code.file;
			if (!(file_handle.handle.fp = VCWD_FOPEN(file_handle.filename, "rb"))) {
				php_printf("Could not open input file: %s\n", file_handle.filename);
				return FAILURE;
			}
			php_execute_script(&file_handle TSRMLS_CC);

		}else {
		}

	} zend_catch {
		/* int exit_status = EG(exit_status); */
	} zend_end_try();

	ngx_http_php_request_clean(TSRMLS_C);

	php_ngx_request_shutdown(TSRMLS_C);

	return 0;
}
