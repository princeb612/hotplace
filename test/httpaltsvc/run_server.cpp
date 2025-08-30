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
 * test
 * curl https://localhost:9000/ -k -v
 * curl https://localhost:9001/ -k -v
 */

#include "sample.hpp"

#define FILENAME_RUN _T (".run")

void api_response_html_handler(network_session *, http_request *request, http_response *response, http_router *router) {
    response->compose(200, "text/html", "<html><body>page - ok<body></html>");
}

void api_response_json_handler(network_session *, http_request *request, http_response *response, http_router *router) {
    response->compose(200, "application/json", R"({"result":"ok"})");
}

std::function<void(network_session *, http_request *, http_response *, http_router *)> default_handler =
    [](network_session *session, http_request *request, http_response *response, http_router *router) -> void {
    basic_stream bs;
    bs << request->get_http_uri().get_uri();
    response->compose(200, "text/html", "<html><body><pre>%s</pre></body></html>", bs.c_str());
};
std::function<void(network_session *, http_request *, http_response *, http_router *)> error_handler =
    [](network_session *session, http_request *request, http_response *response, http_router *router) -> void {
    basic_stream bs;
    bs << request->get_http_uri().get_uri();
    response->compose(200, "text/html", "<html><body>404 Not Found<pre>%s</pre></body></html>", bs.c_str());
};

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
            _logger->colorln("connect %i", session_socket->get_event_socket());
            break;
        case mux_read:
            _logger->colorln("read %i", session_socket->get_event_socket());
            if (option.verbose) {
                _logger->writeln("%.*s", (unsigned)bufsize, buf);
            }

            if (request) {
                http_response response(request);

                /**
                 * Upgrade : commonly used in upgrading HTTP/1.1 connections to WebSocket or HTTP/2.
                 * Alt-Svc : HTTP/1.1 to HTTP/2 or QUIC
                 *           does not mandate client behavior; it's a suggestion.
                 * HSTS    : HTTP Strict Transport Security
                 *           security mechanism enforcing HTTPS-only connections; prevents downgrade attacks.
                 * ALPN    : negotiate the application protocol during the TLS handshake
                 */

                // HTTP/3 not implemented yet ... (studying)
                if ("HTTP/1.1" == request->get_version_str()) {
                    std::string altsvc_fieldvalue = format(R"(h2=":%i"; h3=":%i"; ma=2592000; persist=1)", option.port_h2, option.port_h3);
                    response.get_http_header().add("Alt-Svc", altsvc_fieldvalue);
                } else if ("HTTP/2" == request->get_version_str()) {
                    std::string altsvc_fieldvalue = format(R"(h3=":%i"; ma=2592000; persist=1)", option.port_h3);
                    response.get_http_header().add("Alt-Svc", altsvc_fieldvalue);
                }
                _http_server1->get_http_router().route(session, request, &response);

                response.respond(session);
            }

            break;
        case mux_disconnect:
            _logger->colorln("disconnect %i", session_socket->get_event_socket());
            break;
    }
    return ret;
}

void start_server(t_shared_instance<http_server> &server, const std::string version) {
    const OPTION &option = _cmdline->value();

    http_server_builder builder;

    builder.enable_http(false)
        .enable_https(true)
        .set_tls_certificate("server.crt", "server.key")
        .set_tls_cipher_list("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_8_SHA256:TLS_AES_128_CCM_SHA256")
        .set_tls_verify_peer(0)
        .enable_ipv4(true)
        .enable_ipv6(false)
        .set_handler(consumer_routine);
    if ("HTTP/2" == version) {
        builder.set_port_https(option.port_h2).enable_h2(true);
    } else {
        builder.set_port_https(option.port_h1);
    }
    builder.get_server_conf()
        .set(netserver_config_t::serverconf_concurrent_tls_accept, 1)
        .set(netserver_config_t::serverconf_concurrent_network, 2)
        .set(netserver_config_t::serverconf_concurrent_consume, 2);
    server.make_share(builder.build());

    // content-type, default document
    server->get_http_router()
        .get_html_documents()
        .add_documents_root("/", ".")
        .add_content_type(".html", "text/html")
        .add_content_type(".json", "text/json")
        .add_content_type(".js", "application/javascript")
        .set_default_document("index.html");
    // router
    server->get_http_router()
        .add("/api/html", api_response_html_handler)
        .add("/api/json", api_response_json_handler)
        .add("/api/test", default_handler)
        .add(404, error_handler);
    server->get_http_protocol().set_constraints(protocol_constraints_t::protocol_packet_size, option.packetsize);

    // HTTP/2 Server Push
    if ("HTTP/2" == version) {
        server->get_http_router().get_http2_serverpush().add("/", "/style.css").add("/index.html", "/style.css");
    }

    server->start();
}

void stop_server(t_shared_instance<http_server> &server) { server->stop(); }

return_t simple_http_server1(void *) {
    const OPTION &option = _cmdline->value();

    return_t ret = errorcode_t::success;

    FILE *fp = fopen(FILENAME_RUN, "w");

    fclose(fp);

    __try2 {
        start_server(_http_server1, "HTTP/1.1");
        start_server(_http_server2, "HTTP/2");

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

        stop_server(_http_server1);
        stop_server(_http_server2);
    }
    __finally2 {}

    return ret;
}

void run_server() {
    thread thread1(simple_http_server1, nullptr);
    return_t ret = errorcode_t::success;

    __try2 {
        _test_case.begin("http/1.1 powered by http_server");

        thread1.start();
    }
    __finally2 { thread1.wait(-1); }
}
