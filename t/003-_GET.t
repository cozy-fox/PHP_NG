# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: _GET
_GET
--- config
location = /_get {
    php_content_handler_code '
		echo "_GET[a]: ".$_GET["a"];
		echo "\n_GET[b]: ".$_GET["b"];
	';
}
--- request
GET /_get?a=1&b=2
--- response_body
_GET[a]: 1
_GET[b]: 2