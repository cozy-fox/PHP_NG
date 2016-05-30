# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: _SERVER
_SERVER['REQUEST_METHOD']
--- config
location = /_server {
    content_by_php '
		echo $_SERVER["REQUEST_METHOD"]."\n";
	';
}
--- request
GET /_server
--- response_body
GET

=== TEST 2: _SERVER['DOCUMENT_URI']
_SERVER['DOCUMENT_URI']
--- config
location = /_server {
    content_by_php '
		echo $_SERVER["DOCUMENT_URI"]."\n";
	';
}
--- request
GET /_server
--- response_body
/_server
