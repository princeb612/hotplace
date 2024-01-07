/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *      simple https server implementation
 * @sa  See in the following order : tcpserver1, tcpserver2, tlsserver, httpserver
 *
 * Revision History
 * Date         Name                Description
 */

#include <signal.h>
#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::io;
using namespace hotplace::crypto;
using namespace hotplace::net;

test_case _test_case;

typedef struct _OPTION {
    std::string url;
    int mode;
    int debug;

    _OPTION() : url("https://localhost:9000/"), mode(0), debug(0) {}
} OPTION;

t_shared_instance<cmdline_t<OPTION> > cmdline;
console_color _concolor;

void test_request() {
    _test_case.begin("request");
    // chrome browser request data https://127.0.0.1:9000/test
    const char* input =
        "GET /test HTTP/1.1\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n"
        "Accept-Encoding: gzip, deflate, br\r\n"
        "Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7\r\n"
        "Cache-Control: max-age=0\r\n"
        "Connection: keep-alive\r\n"
        "Content-Length: 2\r\n"
        "Host: 127.0.0.1:9000\r\n"
        "Sec-Fetch-Dest: document\r\n"
        "Sec-Fetch-Mode: navigate\r\n"
        "Sec-Fetch-Site: none\r\n"
        "Sec-Fetch-User: ?1\r\n"
        "Upgrade-Insecure-Requests: 1\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"
        "sec-ch-ua: \"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"\r\n"
        "sec-ch-ua-mobile: ?0\r\n"
        "sec-ch-ua-platform: \"Windows\"\r\n\r\n";

    http_request request;
    request.open(input);

    OPTION& option = cmdline->value();
    if (option.debug) {
        test_case_notimecheck notimecheck(_test_case);

        printf("%s\n", input);
    }

    const char* uri = request.get_uri();
    _test_case.assert(0 == strcmp(uri, "/test"), __FUNCTION__, "uri");

    const char* method = request.get_method();
    _test_case.assert(0 == strcmp(method, "GET"), __FUNCTION__, "method");

    std::string header_accept_encoding;
    request.get_header()->get("Accept-Encoding", header_accept_encoding);
    _test_case.assert(header_accept_encoding == "gzip, deflate, br", __FUNCTION__, "header");
}

void test_response_compose() {
    _test_case.begin("response");

    http_response response;
    response.get_header()->add("Connection", "Keep-Alive");
    response.compose(200, "text/html", "<html><body>hello</body></html>");

    OPTION& option = cmdline->value();
    if (option.debug) {
        test_case_notimecheck notimecheck(_test_case);

        basic_stream bs;
        response.get_response(bs);
        printf("%s\n", bs.c_str());
    }

    _test_case.assert(200 == response.status_code(), __FUNCTION__, "status");
    _test_case.assert(31 == response.content_size(), __FUNCTION__, "Content-Length");
    _test_case.assert(0 == strcmp(response.content_type(), "text/html"), __FUNCTION__, "Content-Type");
}

void test_response_parse() {
    _test_case.begin("response");
    OPTION& option = cmdline->value();

    http_response response;
    std::string wwwauth;
    key_value kv;

    const char* input =
        "HTTP/1.1 401 Unauthorized\r\n"
        "Connection: Keep-Alive\r\n"
        "Content-Length: 42\r\n"
        "Content-Type: text/html\r\n"
        "WWW-Authenticate: Digest realm=\"helloworld\", qop=\"auth,auth-int\", nonce=\"40dc29366886273821be1fcc5e23e9d7e9\", "
        "opaque=\"8be41306f5b9bb30019350c33b182858\"\r\n"
        "\r\n"
        "<html><body>401 Unauthorized</body></html>";

    response.open(input);

    response.get_header()->get("WWW-Authenticate", wwwauth);
    http_header::to_keyvalue(wwwauth, kv);

    if (option.debug) {
        kv.foreach ([&](std::string const& k, std::string const& v, void* param) -> void { printf("%s=%s\n", k.c_str(), v.c_str()); });
    }

    _test_case.assert(401 == response.status_code(), __FUNCTION__, "status");
    std::string content_length;
    response.get_header()->get("Content-Length", content_length);
    _test_case.assert("42" == content_length, __FUNCTION__, "Content-Length");
    _test_case.assert(42 == response.content_size(), __FUNCTION__, "Content-Length");
    _test_case.assert(0 == strcmp(response.content_type(), "text/html"), __FUNCTION__, "Content-Type");
    _test_case.assert(0 == strcmp("auth,auth-int", kv["qop"]), __FUNCTION__, "qop from WWW-Authenticate");
    _test_case.assert(0 == strcmp("40dc29366886273821be1fcc5e23e9d7e9", kv["nonce"]), __FUNCTION__, "nonce from WWW-Authenticate");
}

void test_get() {
    _test_case.begin("get");
    return_t ret = errorcode_t::success;
    OPTION& option = cmdline->value();

    std::function<void(const char*)> cprint = [&](const char* text) -> void {
        std::cout << _concolor.turnon().set_fgcolor(console_color_t::cyan) << text;
        std::cout << _concolor.turnoff() << std::endl;
    };

    __try2 {
        url_info_t url_info;
        split_url(option.url.c_str(), &url_info);

        if ("https" != url_info.protocol) {
            __leave2;
        }

        socket_t sock = 0;

        tls_context_t* handle = nullptr;
        SSL_CTX* x509 = nullptr;
        x509_open_simple(&x509);
        transport_layer_security tls(x509);
        transport_layer_security_client cli(&tls);
        basic_stream bs;

        ret = cli.connect(&sock, &handle, url_info.host.c_str(), url_info.port, 5);
        if (errorcode_t::success == ret) {
            cprint("connected");

            http_request req;
            req.open(format("GET %s HTTP/1.1", url_info.uri.c_str()));
            basic_stream body;
            req.get_request(body);

            cprint("request");
            std::cout << body.c_str() << std::endl;

            size_t cbsent = 0;
            ret = cli.send(sock, handle, body.c_str(), body.size(), &cbsent);
            if (errorcode_t::success == ret) {
                char buf[4];
                size_t sizeread = 0;

                if (0 == option.mode) {
                    ret = cli.read(sock, handle, buf, sizeof(buf), &sizeread);
                    printf("status 0x%08x - %.*s\n", ret, (int)sizeread, buf);
                    while (errorcode_t::more_data == ret) {
                        ret = cli.more(sock, handle, buf, sizeof(buf), &sizeread);
                        printf("status 0x%08x - %.*s\n", ret, (int)sizeread, buf);
                    }
                } else {
                    network_protocol_group group;
                    http_protocol http;
                    network_stream stream_read;
                    network_stream stream_interpreted;
                    group.add(&http);

                    ret = cli.read(sock, handle, buf, sizeof(buf), &sizeread);
                    stream_read.produce(buf, sizeread);
                    while (errorcode_t::more_data == ret) {
                        ret = cli.more(sock, handle, buf, sizeof(buf), &sizeread);
                        stream_read.produce(buf, sizeread);
                    }

                    stream_read.write(&group, &stream_interpreted);
                    network_stream_data* data = nullptr;
                    stream_interpreted.consume(&data);
                    if (data) {
                        cprint("response");
                        printf("%.*s\n", data->size(), data->content());

                        data->release();
                    }
                }
            }  // send
            cli.close(sock, handle);
            cprint("closed");
        }  // connect

        SSL_CTX_free(x509);
    }
    __finally2 {
        // do nothing
    }
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

#if defined _WIN32 || defined _WIN64
    winsock_startup();
#endif
    openssl_startup();
    openssl_thread_setup();

    cmdline.make_share(new cmdline_t<OPTION>);

    *cmdline << cmdarg_t<OPTION>("-u", "url (default https://localhost:9000/)", [&](OPTION& o, char* param) -> void { o.url = param; }).preced().optional()
             << cmdarg_t<OPTION>("-p", "read stream using http_protocol", [&](OPTION& o, char* param) -> void { o.mode = 1; }).optional()
             << cmdarg_t<OPTION>("-d", "debug", [&](OPTION& o, char* param) -> void { o.debug = 1; }).optional();

    cmdline->parse(argc, argv);

    test_request();
    test_response_compose();
    test_response_parse();
    test_get();

    openssl_thread_end();
    openssl_cleanup();

#if defined _WIN32 || defined _WIN64
    winsock_cleanup();
#endif

    _test_case.report(5);
    cmdline->help();
    return _test_case.result();
}
