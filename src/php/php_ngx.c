/**
 *    Copyright(c) 2016 rryqszq4
 *
 *
 */

#include "php_ngx.h"

static int php_ngx_startup(sapi_module_struct *sapi_module)
{
	if (php_module_startup(sapi_module, NULL, 0) == FAILURE){
		return FAILURE;
	}
	return SUCCESS;
}

static int php_ngx_deactivate(TSRMLS_D)
{
	return SUCCESS;
}

static int php_ngx_ub_write(const char *str, uint str_length TSRMLS_DC)
{
	return str_length;
}

static void php_ngx_flush(void *server_context)
{
}

static int php_ngx_header_handler(sapi_header_struct *sapi_header, sapi_header_op_enum op, sapi_headers_struct *sapi_headers TSRMLS_DC)
{
	return 0;
}

static int php_ngx_read_post(char *buffer, uint count_bytes TSRMLS_DC)
{
	return 0;
}

static char* php_ngx_read_cookies(TSRMLS_D)
{
	return NULL;
}

static void php_ngx_register_variables(zval *track_vars_array TSRMLS_DC)
{
	php_import_environment_variables(track_vars_array TSRMLS_CC);

	/*if (SG(request_info).request_method) {
		php_register_variable("REQUEST_METHOD", (char *)SG(request_info).request_method, track_vars_array TSRMLS_CC);
	}
	if (SG(request_info).request_uri){
		php_register_variable("DOCUMENT_URI", (char *)SG(request_info).request_uri, track_vars_array TSRMLS_CC);

	}
	if (SG(request_info).query_string){
		php_register_variable("QUERY_STRING", (char *)SG(request_info).query_string, track_vars_array TSRMLS_CC);
	}*/
}

static void php_ngx_log_message(char *message)
{
}

/* {{{ sapi_module_struct php_ngx_module
*/
sapi_module_struct php_ngx_module = {
	"php-ngx",						/* name */
	"Embed php nginx module",					/* pretty name */

	php_ngx_startup,				/* startup */
	php_module_shutdown_wrapper,	/* shutdown */

	NULL,//php_ngx_activate,				/* activate */
	php_ngx_deactivate,				/* deactivate */

	php_ngx_ub_write,				/* unbuffered write */
	php_ngx_flush,					/* flush */
	NULL,							/* get uid */
	NULL,							/* getenv */

	php_error,						/* error handler */

	php_ngx_header_handler,			/* header handler */
	NULL,							/* send headers handler */
	NULL,							/* send header handler */

	php_ngx_read_post,				/* read POST data */
	php_ngx_read_cookies,			/* read Cookies */

	php_ngx_register_variables,		/* register server variables */
	php_ngx_log_message,			/* Log message */
	NULL,							/* Get request time */
	NULL,							/* Child terminate */

	"",								/* php_ini_path_override */

	NULL,
	NULL,

	NULL,
	NULL,
	NULL,

	0,
#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION > 3)
	0,
#endif

	NULL,

	NULL,

	NULL,
	NULL,

	NULL,

	NULL,
	0,

	NULL,
	NULL,
	NULL
	//STANDARD_SAPI_MODULE_PROPERTIES
};

/* {{{ arginfo ext/standard/dl.c */
ZEND_BEGIN_ARG_INFO(arginfo_dl, 0)
	ZEND_ARG_INFO(0, extension_filename)
ZEND_END_ARG_INFO()
/* }}} */

static const zend_function_entry additional_functions[] = {
	ZEND_FE(dl, arginfo_dl)
	{NULL, NULL, NULL, 0, 0}
};

int php_ngx_module_init(TSRMLS_D)
{
	
#ifdef ZTS
	void ***tsrm_ls = NULL;
#endif

#ifdef HAVE_SIGNAL_H
#if defined(SIGPIPE) && defined(SIG_IGN)
	signal(SIGPIPE, SIG_IGN); /* ignore SIGPIPE in standalone mode so
								 that sockets created via fsockopen()
								 don't kill PHP if the remote site
								 closes it.  in apache|apxs mode apache
								 does that for us!  thies@thieso.net
								 20000419 */
#endif
#endif

#ifdef ZTS
  tsrm_startup(1, 1, 0, NULL);
  tsrm_ls = ts_resource(0);
#endif

  sapi_startup(&php_ngx_module);

#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION > 3)
  php_ngx_module.php_ini_ignore_cwd = 1;
#endif

#ifdef PHP_WIN32
  _fmode = _O_BINARY;			/*sets default for file streams to binary */
  setmode(_fileno(stdin), O_BINARY);		/* make the stdio mode be binary */
  setmode(_fileno(stdout), O_BINARY);		/* make the stdio mode be binary */
  setmode(_fileno(stderr), O_BINARY);		/* make the stdio mode be binary */
#endif

  php_ngx_module.additional_functions = additional_functions;

  php_ngx_module.executable_location = NULL;

  if (php_ngx_module.startup(&php_ngx_module) == FAILURE){
  	return FAILURE;
  }

  return SUCCESS;
}

int php_ngx_request_init(TSRMLS_D)
{
	if (php_request_startup(TSRMLS_C)==FAILURE) {
		return FAILURE;
  	}

  	SG(headers_sent) = 0;
  	SG(request_info).no_headers = 1;
  	php_register_variable("PHP_SELF", "-", NULL TSRMLS_CC);

  	return SUCCESS;
}

void php_ngx_request_shutdown(TSRMLS_D)
{
	SG(headers_sent) = 1;
	php_request_shutdown((void *)0);
}

void php_ngx_module_shutdown(TSRMLS_D)
{
	php_module_shutdown(TSRMLS_C);
	sapi_shutdown();
#ifdef ZTS
	tsrm_shutdown();
#endif
	if (php_ngx_module.ini_entries){
		free(php_ngx_module.ini_entries);
		php_ngx_module.ini_entries = NULL;
	}
}




/* }}} */