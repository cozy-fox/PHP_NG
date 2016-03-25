use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: hello, ngxphp
This is just a simple demonstration of the
echo directive provided by ngxphp.
--- config
location = /t {
    php_content_handler_code '
		echo "hello ngxphp!";
	';
}
--- request
GET /t
--- response_body
hello ngxphp!