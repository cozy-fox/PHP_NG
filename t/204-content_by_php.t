# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: content
--- config
    location /content {
        content_by_php '
            echo "running content\n";
        ';
    }
--- request
GET /content
--- response_body
running content


