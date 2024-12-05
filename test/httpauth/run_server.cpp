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

#include "sample.hpp"

#define FILENAME_RUN _T (".run")

void api_response_html_handler(network_session*, http_request* request, http_response* response, http_router* router) {
    response->compose(200, "text/html", "<html><body>page - ok<body></html>");
}

void api_response_json_handler(network_session*, http_request* request, http_response* response, http_router* router) {
    response->compose(200, "application/json", R"({"result":"ok"})");
}

return_t consume_routine(uint32 type, uint32 data_count, void* data_array[], CALLBACK_CONTROL* callback_control, void* user_context) {
    return_t ret = errorcode_t::success;
    network_session_socket_t* session_socket = (network_session_socket_t*)data_array[0];
    char* buf = (char*)data_array[1];
    size_t bufsize = (size_t)data_array[2];
    network_session* session = (network_session*)data_array[3];
    http_request* request = (http_request*)data_array[4];

    basic_stream bs;
    std::string message;

    const OPTION& option = _cmdline->value();

    switch (type) {
        case mux_connect:
            _logger->colorln("connect %i", session_socket->event_socket);
            break;
        case mux_read:
            _logger->colorln("read %i", session_socket->event_socket);
            if (option.verbose) {
                _logger->writeln("%.*s", (unsigned)bufsize, buf);
            }

            {
                bool use_tls = session->get_server_socket()->support_tls();

                http_response response(request);
                basic_stream bs;

                if (option.verbose) {
                    response.settrace(debug_handler);
                }

                if (use_tls) {
                    // using http_router
                    _http_server->get_http_router().route(session, request, &response);
                } else {
                    // handle wo http_router
                    response.get_http_header().add("Upgrade", "TLS/1.2, HTTP/1.1").add("Connection", "Upgrade");
                    int status_code = 426;
                    response.compose(status_code, "text/html", "<html><body><a href='https://localhost:%d%s'>%d %s</a><br></body></html>", option.port_tls,
                                     request->get_http_uri().get_uri(), status_code, http_resource::get_instance()->load(status_code).c_str());
                }

                response.respond(session);
                fflush(stdout);
            }

            break;
        case mux_disconnect:
            _logger->colorln("disconnect %i", session_socket->event_socket);
            break;
    }
    return ret;
}

return_t simple_http_server(void*) {
    const OPTION& option = _cmdline->value();

    return_t ret = errorcode_t::success;
    http_server_builder builder;

    FILE* fp = fopen(FILENAME_RUN, "w");
    fclose(fp);

    __try2 {
        builder.enable_http(true)
            .set_port_http(option.port)
            .enable_https(true)
            .set_port_https(option.port_tls)
            .set_tls_certificate("server.crt", "server.key")
            .set_tls_cipher_list("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_8_SHA256:TLS_AES_128_CCM_SHA256")
            .set_tls_verify_peer(0)
            .enable_ipv4(true)
            .enable_ipv6(true)
            .set_handler(consume_routine);
        if (option.h2) {
            builder.enable_h2(true);
        }
        builder.get_server_conf()
            .set(netserver_config_t::serverconf_concurrent_tls_accept, 2)
            .set(netserver_config_t::serverconf_concurrent_network, 4)
            .set(netserver_config_t::serverconf_concurrent_consume, 4);
        _http_server.make_share(builder.build());
        // _http_server->get_ipaddr_acl().add_rule("10.10.10.10", false);  // deny

        // Basic Authentication (realm)
        std::string basic_realm = "Hello World";
        // Digest Access Authentication (realm/algorithm/qop/userhash)
        std::string digest_access_realm = "happiness";
        std::string digest_access_realm2 = "testrealm@host.com";
        std::string digest_access_alg = "SHA-256-sess";
        std::string digest_access_alg2 = "SHA-256-sess";  // chrome not support SHA-512, SHA-512-sess, ...
        std::string digest_access_qop = "auth";
        bool digest_access_userhash = true;
        // Bearer Authentication (realm)
        std::string bearer_realm = "hotplace";
        // OAuth 2.0 (realm)
        std::string oauth2_realm = "somewhere over the rainbow";
        basic_stream endpoint_url;
        basic_stream cb_url;
        endpoint_url << "https://localhost:" << option.port_tls;
        cb_url << endpoint_url << "/client/cb";

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
        std::function<void(network_session*, http_request*, http_response*, http_router*)> cb_handler =
            [&](network_session* session, http_request* request, http_response* response, http_router* router) -> void {
            skey_value& kv = request->get_http_uri().get_query_keyvalue();
            std::string code = kv.get("code");
            std::string access_token = kv.get("access_token");
            std::string error = kv.get("error");
            if (error.empty()) {
                if (code.size()) {
                    // Authorization Code Grant
                    http_client client;
                    http_request req;
                    http_response* resp = nullptr;
                    basic_stream bs;
                    bs << "/auth/token?grant_type=authorization_code&code=" << code << "&redirect_uri=" << cb_url << "&client_id=s6BhdRkqt3";

                    req.compose(http_method_t::HTTP_POST, bs.c_str(), "");                             // token endpoint
                    req.get_http_header().add("Authorization", "Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW");  // s6BhdRkqt3:gX1fBat3bV

                    client.set_url(endpoint_url.c_str());
                    client.set_wto(10 * 1000);
                    client.request(req, &resp);
                    if (resp) {
                        *response = *resp;
                        resp->release();
                    }
                } else if (access_token.size()) {
                    // Implitcit Grant
                    response->compose(200, "text/plain", "");
                }
            } else {
                response->compose(401, "text/html", "<html><body>Unauthorized</body></html>");
            }
        };

        // content-type, default document
        _http_server->get_http_router()
            .get_html_documents()
            .add_documents_root("/", ".")
            .add_content_type(".html", "text/html")
            .add_content_type(".json", "text/json")
            .add_content_type(".js", "application/javascript")
            .set_default_document("index.html");

        // router
        _http_server->get_http_router()
            .add("/api/html", api_response_html_handler)
            .add("/api/json", api_response_json_handler)
            .add("/api/test", default_handler)
            .add(404, error_handler)
            // basic authentication
            .add("/auth/basic", default_handler, new basic_authentication_provider(basic_realm))
            // digest access authentication
            .add("/auth/digest", default_handler, new digest_access_authentication_provider(digest_access_realm, digest_access_alg, digest_access_qop))
            .add("/auth/userhash", default_handler,
                 new digest_access_authentication_provider(digest_access_realm2, digest_access_alg2, digest_access_qop, digest_access_userhash))
            // bearer authentication
            .add("/auth/bearer", default_handler, new bearer_authentication_provider(bearer_realm))
            // callback
            .add("/client/cb", cb_handler);

        // authentication
        _http_server->get_http_router()
            .get_oauth2_provider()
            .add(new oauth2_authorization_code_grant_provider)
            .add(new oauth2_implicit_grant_provider)
            .add(new oauth2_resource_owner_password_credentials_grant_provider)
            .add(new oauth2_client_credentials_grant_provider)
            .add(new oauth2_unsupported_provider)
            .set(oauth2_authorization_endpoint, "/auth/authorize")
            .set(oauth2_token_endpoint, "/auth/token")
            .set(oauth2_signpage, "/auth/sign")
            .set(oauth2_signin, "/auth/signin")
            .set_token_endpoint_authentication(new basic_authentication_provider(oauth2_realm))
            .apply(_http_server->get_http_router());

        http_authentication_resolver& resolver = _http_server->get_http_router().get_authenticate_resolver();

        resolver.get_basic_credentials(basic_realm).add("user", "password");
        resolver.get_basic_credentials(oauth2_realm).add("s6BhdRkqt3", "gX1fBat3bV");  // RFC 6749 Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
        resolver.get_digest_credentials(digest_access_realm).add(digest_access_realm, digest_access_alg, "user", "password");
        resolver.get_digest_credentials(digest_access_realm2)
            .add(digest_access_realm2, digest_access_alg2, "Mufasa", "Circle Of Life")
            .add(digest_access_realm2, digest_access_alg2, "user", "password");
        resolver.get_bearer_credentials(bearer_realm).add("clientid", "token");

        resolver.get_oauth2_credentials().insert("s6BhdRkqt3", "gX1fBat3bV", "user", "testapp", cb_url.c_str(), std::list<std::string>());
        resolver.get_custom_credentials().add("user", "password");

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
        _test_case.begin("tls server");

        thread1.start();
    }
    __finally2 { thread1.wait(-1); }
}
