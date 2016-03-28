use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: ini file
ini file
--- http_config
php_ini_path /usr/local/php/etc/php.ini;
--- config
location = /ini {
    php_content_handler_code '
		echo php_ini_loaded_file();
	';
}
--- request
GET /ini
--- response_body
/usr/local/php/etc/php.ini