# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: session
session
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
	';
}
--- request
GET /session
--- response_body
1