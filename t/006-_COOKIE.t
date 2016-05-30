# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: _COOKIE
_COOKIE
--- config
location = /_cookie {
    content_by_php '
		echo "_COOKIE[foo]: ".$_COOKIE["foo"];
		echo "\n_COOKIE[baz]: ".$_COOKIE["baz"];
	';
}
--- request
GET /_cookie
--- more_headers
Cookie: foo=bar; baz=blah
--- response_body
_COOKIE[foo]: bar
_COOKIE[baz]: blah