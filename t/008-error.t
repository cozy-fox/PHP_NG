# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: error
error
--- config
location = /error {
    php_content_handler_code '
		echo "hello ngx_php";
		$a = new abc();
	';
}
--- request
GET /error
--- response_body
hello ngx_php{! Fatal error: Class 'abc' not found in ngx_php run code on line 3 !}
