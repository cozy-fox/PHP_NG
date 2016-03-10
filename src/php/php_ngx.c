/**
 *    Copyright(c) 2016 rryqszq4
 *
 *
 */

#include "php_ngx.h"


 /* {{{ sapi_module_struct php_ngx_module
 */
extern sapi_module_struct php_ngx_module = {
	"php-ngx",						/* name */
	"Embed php nginx module",					/* pretty name */

	php_ngx_startup,				/* startup */
	php_module_shutdown_wrapper,	/* shutdown */

	NULL//php_ngx_activate,				/* activate */
	php_ngx_deactivate,				/* deactivate */

	php_ngx_ub_write,				/* unbuffered write */
	php_ngx_flush,					/* flush */
	NULL,							/* get uid */
	NULL,							/* getenv */

	php_error,						/* error handler */

	NULL,							/* header handler */
	NULL,							/* send headers handler */
	php_ngx_send_headers,			/* send header handler */

	php_ngx_read_post,				/* read POST data */
	php_ngx_read_cookies,			/* read Cookies */

	php_ngx_register_variables,		/* register server variables */
	php_ngx_log_message,			/* Log message */
	NULL,							/* Get request time */
	NULL,							/* Child terminate */

	STANDARD_SAPI_MODULE_PROPERTIES
};

/* {{{ arginfo ext/standard/dl.c */
ZEND_BEGIN_ARG_INFO(arginfo_dl, 0)
	ZEND_ARG_INFO(0, extension_filename)
ZEND_END_ARG_INFO()
/* }}} */

static const zend_function_entry additional_functions[] = {
	ZEND_FE(dl, arginfo_dl)
	{NULL, NULL, NULL}
};

int php_ngx_module_init(TSRMLS_D){
	
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

#ifdef PHP_WIN32
  _fmode = _O_BINARY;			/*sets default for file streams to binary */
  setmode(_fileno(stdin), O_BINARY);		/* make the stdio mode be binary */
  setmode(_fileno(stdout), O_BINARY);		/* make the stdio mode be binary */
  setmode(_fileno(stderr), O_BINARY);		/* make the stdio mode be binary */
#endif

  php_embed_module.additional_functions = additional_functions;

  return SUCCESS;
}

int php_ngx_request_init(TSRMLS_D){
	if (php_request_startup(TSRMLS_C)==FAILURE) {
		return FAILURE;
  	}

  	SG(headers_sent) = 1;
  	SG(request_info).no_headers = 1;
  	php_register_variable("PHP_SELF", "-", NULL TSRMLS_CC);

  	return SUCCESS;
}

void php_ngx_request_shutdown(TSRMLS_D){
	php_request_shutdown((void *)0);

	return void;
}

void php_ngx_module_shutdown(TSRMLS_D){
	php_request_shutdown((void *)0);
	php_module_shutdown(TSRMLS_C);
	sapi_shutdown();
#ifdef ZTS
	tsrm_shutdown();
#endif
	if (php_ngx_module.ini_entries){
		free(php_ngx_module.ini_entries);
		php_ngx_module.ini_entries = NULL;
	}

	return void;
}




/* }}} */