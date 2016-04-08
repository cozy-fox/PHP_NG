# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: _FILES
_FILES
--- config
location = /_files {
    php_content_handler_code '
		echo $_FILES["file1"]["name"]."\n";
		echo $_FILES["file1"]["type"]."\n";
		echo $_FILES["file1"]["size"]."\n";
		echo $_FILES["file1"]["error"]."\n";
	';
}
--- more_headers
Content-Type: multipart/form-data; boundary=---------------------------820127721219505131303151179
--- request eval
qq{POST /_files\n-----------------------------820127721219505131303151179\r
Content-Disposition: form-data; name="file1"; filename="a.txt"\r
Content-Type: text/plain\r
\r
Hello, world\r\n-----------------------------820127721219505131303151179\r
Content-Disposition: form-data; name="test"\r
\r
value\r
\r\n-----------------------------820127721219505131303151179--\r
}
--- response_body
a.txt
text/plain
12
0
