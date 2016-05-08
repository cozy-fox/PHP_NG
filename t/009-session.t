# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket 'no_plan';

no_long_string();
no_diff();

run_tests();

__DATA__

=== TEST 1: session
session
--- http_config
php_ini_path /home/travis/build/rryqszq4/ngx_php/build/php/php.ini;
--- config
location = /session {
    php_content_handler_code '
		session_start();
		$_SESSION["view"] = 1;
		if (session_id()){
			echo $_SESSION["view"];
		}else {
			echo 0;
		}
		session_destroy();
	';
}
--- request
GET /session
--- response_body
1