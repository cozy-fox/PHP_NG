# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: _SERVER
_SERVER['REQUEST_METHOD']
--- config
location = /_server {
    php_content_handler_code '
		echo $_SERVER["REQUEST_METHOD"];
	';
}
--- request
GET /_server
--- response_body
GET