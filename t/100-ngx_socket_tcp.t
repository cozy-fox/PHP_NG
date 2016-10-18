# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket 'no_plan';

no_long_string();
no_diff();

run_tests();

__DATA__

=== TEST 1: ngx_socket_tcp
ngx_socket_tcp
--- config
location = /content_thread_by_php {
    content_thread_by_php "
        header('Content-Type: application/x-javascript; charset=GBK');
        $tcpsock = new ngx_socket_tcp();
        $tcpsock->connect('202.108.37.102',80);
        $tcpsock->send('GET /list=s_sh000001 HTTP/1.0\r\nHost: hq.sinajs.cn\r\nConnection: close\r\n\r\n');
        $res = $tcpsock->receive();
        $tcpsock->close();
        $res = explode('\r\n',$res);
        var_dump($res[0]);
    ";
}
--- request
GET /content_thread_by_php
--- response_body
string(15) "HTTP/1.1 200 OK"

=== TEST 1: ngx_socket_tcp for resolver hostname
ngx_socket_tcp
--- config
resolver 8.8.8.8;
location = /content_thread_by_php {
    content_thread_by_php "
        header('Content-Type: application/x-javascript; charset=GBK');
        $tcpsock = new ngx_socket_tcp();
        $tcpsock->connect('hq.sinajs.cn',80);
        $tcpsock->send('GET /list=s_sh000001 HTTP/1.0\r\nHost: hq.sinajs.cn\r\nConnection: close\r\n\r\n');
        $res = $tcpsock->receive();
        $tcpsock->close();
        $res = explode('\r\n',$res);
        var_dump($res[0]);
    ";
}
--- request
GET /content_thread_by_php
--- response_body
string(15) "HTTP/1.1 200 OK"
