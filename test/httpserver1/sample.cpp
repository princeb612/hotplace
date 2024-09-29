/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *      simple https server implementation
 * @sa  See in the following order : tcpserver1, tcpserver2, tlsserver, httpserver1, httpauth, httpserver2
 *
 * Revision History
 * Date         Name                Description
 *
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
t_shared_instance<logger> _logger;

#define FILENAME_RUN _T (".run")

typedef struct _OPTION {
    int port;
    int port_tls;
    int verbose;

    _OPTION() : port(8080), port_tls(9000), verbose(0) {}
} OPTION;

t_shared_instance<t_cmdline_t<OPTION>> _cmdline;
t_shared_instance<http_server> _http_server;

void api_response_html_handler(network_session *, http_request *request, http_response *response, http_router *router) {
    response->compose(200, "text/html", "<html><body>page - ok<body></html>");
}

void api_response_json_handler(network_session *, http_request *request, http_response *response, http_router *router) {
    response->compose(200, "application/json", R"({"result":"ok"})");
}

void cprint(const char *text, ...) {
    basic_stream bs;
    console_color _concolor;

    bs << _concolor.turnon().set_fgcolor(console_color_t::cyan);
    va_list ap;
    va_start(ap, text);
    bs.vprintf(text, ap);
    va_end(ap);
    bs << _concolor.turnoff();

    _logger->writeln(bs);
}

return_t consume_routine(uint32 type, uint32 data_count, void *data_array[], CALLBACK_CONTROL *callback_control, void *user_context) {
    return_t ret = errorcode_t::success;
    network_session_socket_t *session_socket = (network_session_socket_t *)data_array[0];
    char *buf = (char *)data_array[1];
    size_t bufsize = (size_t)data_array[2];
    network_session *session = (network_session *)data_array[3];
    http_request *request = (http_request *)data_array[4];

    basic_stream bs;
    std::string message;

    const OPTION &option = _cmdline->value();

    switch (type) {
        case mux_connect:
            cprint("connect %i", session_socket->event_socket);
            break;
        case mux_read:
            cprint("read %i", session_socket->event_socket);
            if (option.verbose) {
                _logger->writeln("%.*s", (unsigned)bufsize, buf);
            }

            {
                bool use_tls = session->get_server_socket()->support_tls();

                http_response response(request);
                basic_stream bs;

                if (use_tls) {
                    // using http_router
                    _http_server->get_http_router().route(session, request, &response);
                } else {
                    // handle wo http_router
                    response.get_http_header().add("Upgrade", "TLS/1.2, HTTP/1.1").add("Connection", "Upgrade");
                    int status_code = 426;
                    response.compose(status_code, "text/html",
                                     "<html><body><a href='https://localhost:%d%s'>%d "
                                     "%s</a><br></body></html>",
                                     option.port_tls, request->get_http_uri().get_uri(), status_code, http_resource::get_instance()->load(status_code).c_str());
                }

                if (option.verbose) {
                    cprint("send %i", session_socket->event_socket);
                    basic_stream resp;
                    response.get_response(resp);
                    _logger->dump(resp);
                }

                response.respond(session);
                fflush(stdout);
            }

            break;
        case mux_disconnect:
            cprint("disconnect %i", session_socket->event_socket);
            break;
    }
    return ret;
}

return_t simple_http_server(void *) {
    const OPTION &option = _cmdline->value();

    return_t ret = errorcode_t::success;
    http_server_builder builder;

    FILE *fp = fopen(FILENAME_RUN, "w");

    fclose(fp);

    __try2 {
        builder.enable_http(true)
            .set_port_http(option.port)
            .enable_https(true)
            .set_port_https(option.port_tls)
            .set_tls_certificate("server.crt", "server.key")
            .set_tls_cipher_list(
                "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_"
                "GCM_SHA256:TLS_AES_128_CCM_8_SHA256:TLS_AES_128_CCM_SHA256")
            .set_tls_verify_peer(0)
            .enable_ipv4(true)
            .enable_ipv6(true)
            .set_handler(consume_routine);
        builder.get_server_conf()
            .set(netserver_config_t::serverconf_concurrent_tls_accept, 2)
            .set(netserver_config_t::serverconf_concurrent_network, 4)
            .set(netserver_config_t::serverconf_concurrent_consume, 4);
        _http_server.make_share(builder.build());

        std::function<void(network_session *, http_request *, http_response *, http_router *)> default_handler =
            [&](network_session *session, http_request *request, http_response *response, http_router *router) -> void {
            basic_stream bs;
            request->get_request(bs);
            response->compose(200, "text/html", "<html><body><pre>%s</pre></body></html>", bs.c_str());
        };
        std::function<void(network_session *, http_request *, http_response *, http_router *)> error_handler =
            [&](network_session *session, http_request *request, http_response *response, http_router *router) -> void {
            basic_stream bs;
            request->get_request(bs);
            response->compose(200, "text/html", "<html><body>404 Not Found<pre>%s</pre></body></html>", bs.c_str());
        };

        _http_server->get_http_router()
            .get_html_documents()
            .add_documents_root("/", ".")
            .add_content_type(".html", "text/html")
            .add_content_type(".json", "text/json")
            .set_default_document("index.html");

        _http_server
            ->get_http_router()
            // http_router
            .add("/api/html", api_response_html_handler)
            .add("/api/json", api_response_json_handler)
            .add("/api/test", default_handler)
            .add(404, error_handler);

        _http_server->get_http_protocol().set_constraints(protocol_constraints_t::protocol_packet_size,
                                                          1 << 12);  // constraints maximum packet size to 4KB

        _http_server->start();

        while (true) {
            msleep(1000);

#if defined __linux__
            int chk = access(FILENAME_RUN, F_OK);
            if (errorcode_t::success != chk) {
                break;
            }
#elif defined _WIN32 || defined _WIN64
            uint32 dwAttrib = GetFileAttributes(FILENAME_RUN);
            if (INVALID_FILE_ATTRIBUTES == dwAttrib) {
                break;
            }
#endif
        }

        _http_server->stop();
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

void run_server() {
    thread thread1(simple_http_server, nullptr);
    return_t ret = errorcode_t::success;

    __try2 {
        _test_case.begin("http/1.1 powered by http_server");

        thread1.start();
    }
    __finally2 { thread1.wait(-1); }
}

int main(int argc, char **argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    *_cmdline << t_cmdarg_t<OPTION>("-h", "http  port (default 8080)", [&](OPTION &o, char *param) -> void { o.port = atoi(param); }).preced().optional()
              << t_cmdarg_t<OPTION>("-s", "https port (default 9000)", [&](OPTION &o, char *param) -> void { o.port_tls = atoi(param); }).preced().optional()
              << t_cmdarg_t<OPTION>("-v", "verbose", [&](OPTION &o, char *param) -> void { o.verbose = 1; }).optional();

    _cmdline->parse(argc, argv);

    const OPTION &option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose).set(logger_t::logger_flush_time, 0).set(logger_t::logger_flush_size, 0);
    _logger.make_share(builder.build());

    if (option.verbose) {
        // openssl ERR_get_error_all/ERR_get_error_line_data
        set_trace_option(trace_option_t::trace_bt | trace_option_t::trace_except);
    }

#if defined _WIN32 || defined _WIN64
    winsock_startup();
#endif
    openssl_startup();
    openssl_thread_setup();

    run_server();

    openssl_thread_end();
    openssl_cleanup();

#if defined _WIN32 || defined _WIN64
    winsock_cleanup();
#endif

    _logger->flush();

    _test_case.report();
    _cmdline->help();
    return _test_case.result();
}
