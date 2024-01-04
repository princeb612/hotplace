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

    _OPTION() : url("https://localhost:9000/"), mode(0) {}
} OPTION;

t_shared_instance<cmdline_t<OPTION> > cmdline;

void test() {
    return_t ret = errorcode_t::success;
    OPTION& option = cmdline->value();

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

        ret = cli.connect(&sock, &handle, url_info.host.c_str(), url_info.port, 5);
        if (errorcode_t::success == ret) {
            printf("connected %d\n", sock);

            http_request req;
            req.open(format("GET %s HTTP/1.1", url_info.uri.c_str()));
            basic_stream body;
            req.get_request(body);

            basic_stream bs;
            dump_memory(body.data(), body.size(), &bs);
            printf("request\n%s\n", bs.c_str());

            size_t cbsent = 0;
            ret = cli.send(sock, handle, body.c_str(), body.size(), &cbsent);
            printf("sent %zi\n", cbsent);
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
                        printf("recv %zi\n", data->size());

                        basic_stream bs;
                        dump_memory((byte_t*)data->content(), data->size(), &bs);
                        printf("%s\n", bs.c_str());
                        data->release();
                    }
                }
            }  // send
            cli.close(sock, handle);
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
    *cmdline << cmdarg_t<OPTION>("-u", "url", [&](OPTION& o, char* param) -> void { o.url = param; }).preced().optional()
             << cmdarg_t<OPTION>("-p", "read stream using http_protocol", [&](OPTION& o, char* param) -> void { o.mode = 1; }).optional();

    cmdline->parse(argc, argv);

    test();

    openssl_thread_end();
    openssl_cleanup();

#if defined _WIN32 || defined _WIN64
    winsock_cleanup();
#endif

    _test_case.report();
    cmdline->help();
    return _test_case.result();
}
