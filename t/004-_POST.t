# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: _POST
_POST
--- config
location = /t {
    content_by_php '
		echo "_POST[a]: ".$_POST["a"];
		echo "\n_POST[b]: ".$_POST["b"];
	';
}
--- more_headers
Content-type: application/x-www-form-urlencoded
--- request
POST /t
a=1&b=2
--- response_body
_POST[a]: 1
_POST[b]: 2