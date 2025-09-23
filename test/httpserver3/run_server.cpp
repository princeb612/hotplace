/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *      simple HTTP/3 server implementation
 * @sa  See in the following order : tcpserver1, tcpserver2, tlsserver, httpserver1, httpauth, httpserver2, dtlsserver, httpserver3
 *
 * Revision History
 * Date         Name                Description
 *
 * @comments
 *      debug w/ curl
 *      curl -v -k https://localhost:9000 --http3
 */

#include "sample.hpp"

#define FILENAME_RUN _T (".run")

void api_response_html_handler(network_session*, http_request* request, http_response* response, http_router* router) {
    response->compose(200, "text/html", "<html><body>page - ok<body></html>");
}

void api_response_json_handler(network_session*, http_request* request, http_response* response, http_router* router) {
    response->compose(200, "application/json", R"({"result":"ok"})");
}

return_t consumer_routine(uint32 type, uint32 data_count, void* data_array[], CALLBACK_CONTROL* callback_control, void* user_context) {
    return_t ret = errorcode_t::success;
    netsocket_t* session_socket = (netsocket_t*)data_array[0];
    char* buf = (char*)data_array[1];
    size_t bufsize = (size_t)data_array[2];
    network_session* session = (network_session*)data_array[3];
    http_request* request = (http_request*)data_array[4];

    binary_t bin;
    basic_stream bs;
    std::string message;

    const OPTION& option = _cmdline->value();

    switch (type) {
        case mux_connect:
            break;
        case mux_read:
            if (request) {
                http_response response(request);
                _http_server->get_http_router().route(session, request, &response);
                response.respond(session);
            }
            break;
        case mux_disconnect:
            break;
    }

    return ret;
}

return_t simple_http2_server(void*) {
    const OPTION& option = _cmdline->value();

    return_t ret = errorcode_t::success;

    FILE* fp = fopen(FILENAME_RUN, "w");

    fclose(fp);

    __try2 {
        _test_case.begin("HTTP/3 powered by http_server");

        server_socket_adapter* adapter = nullptr;
        {
            server_socket_builder builder;
            adapter = builder.set(socket_scheme_trial).build_adapter();
        }
        if (nullptr == adapter) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        {
            std::string ciphersuites;
            if (option.cs.empty()) {
                ciphersuites = "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256";
            } else {
                ciphersuites = option.cs;
            }

            http_server_builder builder;
            builder.set(adapter)
                .enable_http(false)  // disable http scheme
                .set_port_http(option.port)
                .enable_https(true)  // enable https scheme
                .set_port_https(option.port_tls)
                .set_tls_certificate("ecdsa.crt", "ecdsa.key")  // RSA certificate
                .set_tls_verify_peer(0)                         // self-signed certificate
                .enable_ipv4(true)                              // enable IPv4
                .enable_ipv6(true)                              // enable IPv6
                .enable_h1(false)                               //
                .enable_h2(false)                               //
                .enable_h3(true)                                //
                .set_handler(consumer_routine)
                .set_tls_cipher_list(ciphersuites);

            if (option.content_encoding) {
                builder.allow_content_encoding("deflate, gzip");
            }

            builder.get_server_conf()
                .set(netserver_config_t::serverconf_concurrent_tls_accept, 2)
                .set(netserver_config_t::serverconf_concurrent_network, 4)
                .set(netserver_config_t::serverconf_concurrent_consume, 4);

            _http_server.make_share(builder.build());
        }

        _http_server->get_http_protocol().set_constraints(protocol_constraints_t::protocol_packet_size, 1 << 14);
        _http_server->get_http2_protocol().set_constraints(protocol_constraints_t::protocol_packet_size, 1 << 16);  // default window size 64k

        std::function<void(network_session*, http_request*, http_response*, http_router*)> default_handler =
            [&](network_session* session, http_request* request, http_response* response, http_router* router) -> void {
            basic_stream bs;
            bs << request->get_http_uri().get_uri();
            response->compose(200, "text/html", "<html><body><pre>%s</pre></body></html>", bs.c_str());
        };
        std::function<void(network_session*, http_request*, http_response*, http_router*)> error_handler =
            [&](network_session* session, http_request* request, http_response* response, http_router* router) -> void {
            basic_stream bs;
            bs << request->get_http_uri().get_uri();
            response->compose(200, "text/html", "<html><body>404 Not Found<pre>%s</pre></body></html>", bs.c_str());
        };

        // content-type, default document
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

        // router
        _http_server->get_http_router()
            .add("/api/html", api_response_html_handler)
            .add("/api/json", api_response_json_handler)
            .add("/api/test", default_handler);

        _http_server->get_http_router().get_http2_serverpush().add("/index.html", "/style.css").add("/index.html", "/blah.js");

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
    __finally2 {}

    return ret;
}

void run_server() {
    thread thread1(simple_http2_server, nullptr);
    return_t ret = errorcode_t::success;

    __try2 { thread1.start(); }
    __finally2 { thread1.wait(-1); }
}
