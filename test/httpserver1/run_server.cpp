/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *      simple HTTP/1.1 server implementation
 * @sa  See in the following order : tcpserver1, tcpserver2, tlsserver, httpserver1, httpauth, httpserver2
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include "sample.hpp"

#define FILENAME_RUN _T (".run")

void api_response_html_handler(network_session *, http_request *request, http_response *response, http_router *router) {
    response->compose(200, "text/html", "<html><body>page - ok<body></html>");
}

void api_response_json_handler(network_session *, http_request *request, http_response *response, http_router *router) {
    response->compose(200, "application/json", R"({"result":"ok"})");
}

return_t consumer_routine(uint32 type, uint32 data_count, void *data_array[], CALLBACK_CONTROL *callback_control, void *user_context) {
    return_t ret = errorcode_t::success;
    netsocket_t *session_socket = (netsocket_t *)data_array[0];
    char *buf = (char *)data_array[1];
    size_t bufsize = (size_t)data_array[2];
    network_session *session = (network_session *)data_array[3];
    http_request *request = (http_request *)data_array[4];

    basic_stream bs;
    std::string message;

    const OPTION &option = _cmdline->value();

    switch (type) {
        case mux_connect:
            break;
        case mux_read:
            if (option.verbose) {
                _logger->writeln("%.*s", (unsigned)bufsize, buf);
            }

            {
                bool use_tls = session->get_server_socket()->support_tls();

                http_response response(request);

                if (use_tls) {
                    // using http_router
                    _http_server->get_http_router().route(session, request, &response);
                } else {
                    /**
                     * Upgrade : commonly used in upgrading HTTP/1.1 connections to WebSocket or HTTP/2.
                     * Alt-Svc : HTTP/1.1 to HTTP/2 or QUIC
                     *           does not mandate client behavior; it's a suggestion.
                     * HSTS    : HTTP Strict Transport Security
                     *           security mechanism enforcing HTTPS-only connections; prevents downgrade attacks.
                     * ALPN    : negotiate the application protocol during the TLS handshake
                     */
                    if (0) {
                        /* chrome, edge - not support upgrade */
                        const std::string &connection = request->get_http_header().get("Connection");
                        const std::string &upgrade = request->get_http_header().get("Upgrade");
                        if (("Upgrade" == connection) && (upgrade.find("TLS/1.3"))) {
                            // RFC 2817 3.3 Server Acceptance of Upgrade Request
                            response.compose(101);  // Switching Protocols
                        } else {
                            // RFC 2817 4.2 Mandatory Advertisement
                            response.get_http_header().add("Upgrade", "TLS/1.3, HTTP/1.1").add("Connection", "Upgrade");
                            int status_code = 426;  // Upgrade Required
                            response.compose(status_code, "text/html", "<html><body><a href='https://localhost:%d%s'>%d %s</a><br></body></html>",
                                             option.port_tls, request->get_http_uri().get_uri(), status_code,
                                             http_resource::get_instance()->load(status_code).c_str());
                        }
                    } else {
                        /* 301 Move Permanently */
                        std::string host = request->get_http_header().get("Host");
                        replace(host, format(":%i", option.port), format(":%i", option.port_tls));
                        response.get_http_header().add("Location", format("https://%s", host.c_str()));
                        response.compose(301);
                    }
                }

                response.respond(session);
            }

            break;
        case mux_disconnect:
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
        builder.set(new openssl_server_socket_adapter)
            .enable_http(true)
            .set_port_http(option.port)
            .enable_https(true)
            .set_port_https(option.port_tls)
            .set_tls_certificate("server.crt", "server.key")
            .set_tls_cipher_list("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_8_SHA256:TLS_AES_128_CCM_SHA256")
            .set_tls_verify_peer(0)
            .enable_ipv4(true)
            .enable_ipv6(true)
            .set_handler(consumer_routine);
        if (option.content_encoding) {
            builder.allow_content_encoding("deflate, gzip");
        }
        builder.get_server_conf()
            .set(netserver_config_t::serverconf_concurrent_tls_accept, 2)
            .set(netserver_config_t::serverconf_concurrent_network, 4)
            .set(netserver_config_t::serverconf_concurrent_consume, 4);
        _http_server.make_share(builder.build());

        _http_server->get_http_protocol().set_constraints(protocol_constraints_t::protocol_packet_size, 1 << 14);

        std::function<void(network_session *, http_request *, http_response *, http_router *)> default_handler =
            [&](network_session *session, http_request *request, http_response *response, http_router *router) -> void {
            basic_stream bs;
            bs << request->get_http_uri().get_uri();
            response->compose(200, "text/html", "<html><body><pre>%s</pre></body></html>", bs.c_str());
        };
        std::function<void(network_session *, http_request *, http_response *, http_router *)> error_handler =
            [&](network_session *session, http_request *request, http_response *response, http_router *router) -> void {
            basic_stream bs;
            bs << request->get_http_uri().get_uri();
            response->compose(200, "text/html", "<html><body>404 Not Found<pre>%s</pre></body></html>", bs.c_str());
        };

        _http_server->get_http_router()
            .get_html_documents()
            .add_documents_root("/", ".")
            .add_content_type(".css", "text/css")
            .add_content_type(".html", "text/html")
            .add_content_type(".ico", "image/image/vnd.microsoft.icon")
            .add_content_type(".jpeg", "image/jpeg")
            .add_content_type(".json", "text/json")
            .add_content_type(".js", "application/javascript")
            .set_default_document("index.html");

        _http_server
            ->get_http_router()
            // http_router
            .add("/api/html", api_response_html_handler)
            .add("/api/json", api_response_json_handler)
            .add("/api/test", default_handler)
            .add(404, error_handler);

        // // constraints maximum packet size to 4KB
        _http_server->get_http_protocol().set_constraints(protocol_constraints_t::protocol_packet_size, 1 << 12);

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
