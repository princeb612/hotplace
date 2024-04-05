/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *      simple https server implementation
 * @sa  See in the following order : tcpserver1, tcpserver2, tlsserver, httpserver, httpauth
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

#define FILENAME_RUN _T (".run")

typedef struct _OPTION {
    int port;
    int port_tls;
    int debug;

    _OPTION() : port(8080), port_tls(9000), debug(0) {}
} OPTION;

t_shared_instance<cmdline_t<OPTION> > cmdline;
t_shared_instance<http_server> _http_server;

void api_test_handler(network_session*, http_request* request, http_response* response, http_router* router) {
    response->compose(200, "text/html", "<html><body>page - ok<body></html>");
}

void api_v1_test_handler(network_session*, http_request* request, http_response* response, http_router* router) {
    response->compose(200, "application/json", "{\"result\":\"ok\"}");
}

void cprint(const char* text, ...) {
    console_color _concolor;

    std::cout << _concolor.turnon().set_fgcolor(console_color_t::cyan);
    va_list ap;
    va_start(ap, text);
    vprintf(text, ap);
    va_end(ap);
    std::cout << _concolor.turnoff() << std::endl;
}

return_t network_routine(uint32 type, uint32 data_count, void* data_array[], CALLBACK_CONTROL* callback_control, void* user_context) {
    return_t ret = errorcode_t::success;
    net_session_socket_t* session_socket = (net_session_socket_t*)data_array[0];
    network_session* session = (network_session*)data_array[3];
    char* buf = (char*)data_array[1];
    size_t bufsize = (size_t)data_array[2];

    // t_shared_instance<http_server> server = _http_server;

    basic_stream bs;
    std::string message;

    OPTION& option = cmdline->value();

    switch (type) {
        case mux_connect:
            cprint("connect %i", session_socket->client_socket);
            break;
        case mux_read:
            cprint("read %i", session_socket->client_socket);
            if (option.debug) {
                printf("%.*s\n", (unsigned)bufsize, buf);
            }

            {
                arch_t use_tls = 0;
                session->get_server_socket()->query(server_socket_query_t::query_support_tls, &use_tls);

                http_request request;
                http_response response(&request);
                basic_stream bs;
                request.open(buf, bufsize);

                if (0) {
                    std::string encoding;

                    std::cout << "uri : " << request.get_http_uri().get_uri() << std::endl;
                    std::cout << "method : " << request.get_method() << std::endl;

                    /* URI, URL, query */
                    http_uri& uri = request.get_http_uri();
                    uri.get_query_keyvalue().foreach (
                        [&](std::string const& key, std::string const& value, void* param) -> void { std::cout << key << " : " << value << std::endl; });

                    std::cout << "tls : " << use_tls << std::endl;

                    /* header */
                    request.get_http_header().get("Accept-Encoding", encoding);
                    std::cout << "encoding : " << encoding.c_str() << std::endl << std::endl;
                }

                if (use_tls) {
                    // using http_router
                    _http_server->get_http_router().route(session, &request, &response);
                } else {
                    // handle wo http_router
                    response.get_http_header().add("Upgrade", "TLS/1.2, HTTP/1.1").add("Connection", "Upgrade");
                    int status_code = 426;
                    response.compose(status_code, "text/html", "<html><body><a href='https://localhost:%d%s'>%d %s</a><br></body></html>", option.port_tls,
                                     request.get_http_uri().get_uri(), status_code, http_resource::get_instance()->load(status_code).c_str());
                }

                if (option.debug) {
                    cprint("send %i", session_socket->client_socket);
                    basic_stream resp;
                    response.get_response(resp);
                    basic_stream temp;
                    dump_memory(resp, &temp);
                    printf("%s\n", temp.c_str());
                }

                response.respond(session);
                fflush(stdout);
            }

            break;
        case mux_disconnect:
            cprint("disconnect %i", session_socket->client_socket);
            break;
    }
    return ret;
}

return_t echo_server(void*) {
    OPTION& option = cmdline->value();

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
            .enable_ip4(true)
            .enable_ip6(true)
            .set_handler(network_routine)
            .set_concurrent(2);
        _http_server.make_share(builder.build());
        // _http_server->get_ipaddr_acl().add_rule("10.10.10.10", false);  // deny

        // Basic Authentication (realm)
        std::string basic_realm = "Hello World";
        // Digest Access Authentication (realm/algorithm/qop/userhash)
        std::string digest_access_realm = "happiness";
        std::string digest_access_realm2 = "testrealm@host.com";
        std::string digest_access_alg = "SHA-256-sess";
        std::string digest_access_alg2 = "SHA-512-256-sess";
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
            request->get_request(bs);
            response->compose(200, "text/html", "<html><body><pre>%s</pre></body></html>", bs.c_str());
        };
        std::function<void(network_session*, http_request*, http_response*, http_router*)> error_handler =
            [&](network_session* session, http_request* request, http_response* response, http_router* router) -> void {
            basic_stream bs;
            request->get_request(bs);
            response->compose(200, "text/html", "<html><body>404 Not Found<pre>%s</pre></body></html>", bs.c_str());
        };
        std::function<void(network_session*, http_request*, http_response*, http_router*)> auth_handler =
            [&](network_session* session, http_request* request, http_response* response, http_router* router) -> void {
            // studying RFC 6749

            key_value& kv = request->get_http_uri().get_query_keyvalue();

            std::string response_type = kv.get("response_type");
            std::string client_id = kv.get("client_id");
            std::string redirect_uri = kv.get("redirect_uri");
            std::string state = kv.get("state");
            basic_stream response_location;

            if ("code" == response_type) {  // Authorization Code Grant
                return_t check = router->get_authenticate_resolver().get_oauth2_credentials().check(client_id, redirect_uri);
                if (errorcode_t::success == check) {
                    response->get_http_header().add("Location", "/signin.html");
                    response->compose(302);

                    session->get_session_data()->set("client_id", client_id);
                    session->get_session_data()->set("redirect_uri", redirect_uri);
                    session->get_session_data()->set("state", state);
                } else {
                    // 4.1.2.1.  Error Response
                    // HTTP/1.1 302 Found
                    // Location: https://client.example.com/cb?error=access_denied&state=xyz
                    std::string errorcode;
                    error_advisor* advisor = error_advisor::get_instance();
                    advisor->error_code(check, errorcode);
                    response_location << redirect_uri << "?error=" << errorcode << "&state=" << state;
                    response->get_http_header().add("Location", response_location.c_str());
                    response->compose(302);
                }
            } else if ("token" == response_type) {  // Implitcit Grant
                return_t check = router->get_authenticate_resolver().get_oauth2_credentials().check(client_id, redirect_uri);
                if (errorcode_t::success == check) {
                    std::string access_token;
                    std::string refresh_token;
                    uint16 expire = 60 * 60;

                    router->get_authenticate_resolver().get_oauth2_credentials().grant(access_token, refresh_token, client_id, expire);

                    response->get_http_header().clear().add("Cache-Control", "no-store").add("Pragma", "no-cache");
                    response_location << redirect_uri << "#access_token=" << access_token << "&state=" << state << "&expire_in=" << expire;
                    response->get_http_header().add("Location", response_location.c_str());
                    response->compose(302);
                } else {
                    std::string errorcode;
                    error_advisor* advisor = error_advisor::get_instance();
                    advisor->error_code(check, errorcode);
                    response_location << redirect_uri << "?error=" << errorcode << "&state=" << state;
                    response->get_http_header().add("Location", response_location.c_str());
                    response->compose(302);
                }
            } else {
                response_location << redirect_uri << "?error="
                                  << "invalid_request"
                                  << "&state=" << state;
                response->get_http_header().add("Location", response_location.c_str());
                response->compose(302);
            }
        };
        std::function<void(network_session*, http_request*, http_response*, http_router*)> signin_handler =
            [&](network_session* session, http_request* request, http_response* response, http_router* router) -> void {
            basic_stream resp;
            key_value& kv = request->get_http_uri().get_query_keyvalue();
            std::string username = kv.get("user");
            std::string password = kv.get("pass");
            std::string redirect_uri = session->get_session_data()->get("redirect_uri");
            std::string state = session->get_session_data()->get("state");

            bool test = router->get_authenticate_resolver().get_custom_credentials().verify(nullptr, username, password);
            if (test) {
                // RFC 6749 4.1.2.  Authorization Response
                // HTTP/1.1 302 Found
                // Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA
                std::string code;
                router->get_authenticate_resolver().get_oauth2_credentials().grant_code(code);
                resp << redirect_uri << "?code=" << code << "&state=" << state;
                response->get_http_header().add("Location", resp.c_str());
                response->compose(302);

                session->get_session_data()->set("code", code);
            } else {
                resp << redirect_uri << "?error=access_denied&state=" << state;
                response->get_http_header().add("Location", resp.c_str());
                response->compose(302);
            }
        };
        std::function<void(network_session*, http_request*, http_response*, http_router*)> cb_handler =
            [&](network_session* session, http_request* request, http_response* response, http_router* router) -> void {
            key_value& kv = request->get_http_uri().get_query_keyvalue();
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
                    client.set_ttl(10 * 1000);
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
        std::function<void(network_session*, http_request*, http_response*, http_router*)> token_handler =
            [&](network_session* session, http_request* request, http_response* response, http_router* router) -> void {
            key_value& kv = request->get_http_uri().get_query_keyvalue();
            basic_stream body;
            json_t* root = nullptr;
            std::string grant_type = kv.get("grant_type");

            __try2 {
                root = json_object();
                if (nullptr == root) {
                    __leave2;
                }

                std::string access_token;
                std::string refresh_token;
                uint16 expire = 60 * 60;

                if ("authorization_code" == grant_type) {
                    // Authorization Code Grant
                    std::string code = kv.get("code");
                    return_t test = router->get_authenticate_resolver().get_oauth2_credentials().verify_grant_code(code);
                    if (errorcode_t::success == test) {
                        router->get_authenticate_resolver().get_oauth2_credentials().grant(access_token, refresh_token, kv.get("client_id"), expire);
                        response->get_http_header().clear().add("Cache-Control", "no-store").add("Pragma", "no-cache");

                        json_object_set_new(root, "access_token", json_string(access_token.c_str()));
                        json_object_set_new(root, "token_type", json_string("example"));
                        json_object_set_new(root, "expire_in", json_integer(expire));
                        json_object_set_new(root, "refresh_token", json_string(refresh_token.c_str()));
                        json_object_set_new(root, "example_parameter", json_string("example_value"));
                    } else {
                        json_object_set_new(root, "error", json_string("invalid_request"));
                    }
                } else if ("password" == grant_type) {
                    // Resource Owner Password Credentials Grant

                    std::string username = kv.get("username");
                    std::string password = kv.get("password");

                    bool test = router->get_authenticate_resolver().get_custom_credentials().verify(nullptr, username, password);
                    if (test) {
                        router->get_authenticate_resolver().get_oauth2_credentials().grant(access_token, refresh_token, kv.get("client_id"), expire);
                        response->get_http_header().clear().add("Cache-Control", "no-store").add("Pragma", "no-cache");

                        json_object_set_new(root, "access_token", json_string(access_token.c_str()));
                        json_object_set_new(root, "token_type", json_string("example"));
                        json_object_set_new(root, "expire_in", json_integer(expire));
                        json_object_set_new(root, "refresh_token", json_string(refresh_token.c_str()));
                        json_object_set_new(root, "example_parameter", json_string("example_value"));
                    } else {
                        json_object_set_new(root, "error", json_string("access_denied"));
                    }
                } else if ("client_credentials" == grant_type) {
                    // Client Credentials Grant

                    router->get_authenticate_resolver().get_oauth2_credentials().grant(access_token, refresh_token, kv.get("client_id"), expire);
                    response->get_http_header().clear().add("Cache-Control", "no-store").add("Pragma", "no-cache");

                    json_object_set_new(root, "access_token", json_string(access_token.c_str()));
                    json_object_set_new(root, "token_type", json_string("example"));
                    json_object_set_new(root, "expire_in", json_integer(expire));
                    json_object_set_new(root, "refresh_token", json_string(refresh_token.c_str()));
                    json_object_set_new(root, "example_parameter", json_string("example_value"));
                } else {
                    json_object_set_new(root, "error", json_string("unsupported_grant_type"));
                }
            }
            __finally2 {
                if (root) {
                    char* contents = json_dumps(root, JOSE_JSON_FORMAT);
                    if (contents) {
                        body = contents;
                        free(contents);
                    }
                    json_decref(root);
                } else {
                    body << "{\"error\":\"server_error\"}";
                }
            }

            response->compose(200, "application/json", body.c_str());
        };

        _http_server->get_http_router()
            .get_html_documents()
            .add_documents_root("/", ".")
            .add_content_type(".html", "text/html")
            .add_content_type(".json", "text/json")
            .set_default_document("index.html");

        _http_server->get_http_router()
            .add("/api/test", api_test_handler)
            .add("/api/v1/test", api_v1_test_handler)
            .add("/test", default_handler)
            .add(404, error_handler)
            // basic authentication
            .add("/auth/basic", default_handler, new basic_authentication_provider(basic_realm))
            // digest access authentication
            .add("/auth/digest", default_handler,
                 new digest_access_authentication_provider(digest_access_realm, digest_access_alg, digest_access_qop, digest_access_userhash))
            .add("/auth/digest2", default_handler, new digest_access_authentication_provider(digest_access_realm2, "", digest_access_qop))
            // bearer authentication
            .add("/auth/bearer", default_handler, new bearer_authentication_provider(bearer_realm))
            // studying RFC 6749 4.1. Authorization Code Grant
            // authorization endpoint
            .add("/auth/authorize", auth_handler)
            .add("/auth/signin", signin_handler)
            // callback
            .add("/client/cb", cb_handler)
            // token endpoint
            .add("/auth/token", token_handler, new basic_authentication_provider(oauth2_realm));

        http_authentication_resolver& resolver = _http_server->get_http_router().get_authenticate_resolver();

        resolver.get_basic_credentials(basic_realm).add("user", "password");
        resolver.get_basic_credentials(oauth2_realm).add("s6BhdRkqt3", "gX1fBat3bV");  // RFC 6749 Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
        resolver.get_digest_credentials(digest_access_realm).add(digest_access_realm, digest_access_alg, "user", "password");
        resolver.get_digest_credentials(digest_access_realm2).add(digest_access_realm2, digest_access_alg2, "Mufasa", "Circle Of Life");
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

void test_tlsserver() {
    thread thread1(echo_server, nullptr);
    return_t ret = errorcode_t::success;

    __try2 {
        _test_case.begin("tls server");

        thread1.start();
    }
    __finally2 { thread1.wait(-1); }
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    cmdline.make_share(new cmdline_t<OPTION>);
    *cmdline << cmdarg_t<OPTION>("-h", "http  port (default 80)", [&](OPTION& o, char* param) -> void { o.port = atoi(param); }).preced().optional()
             << cmdarg_t<OPTION>("-s", "https port (default 9000)", [&](OPTION& o, char* param) -> void { o.port_tls = atoi(param); }).preced().optional()
             << cmdarg_t<OPTION>("-d", "debug", [&](OPTION& o, char* param) -> void { o.debug = 1; }).optional();

    cmdline->parse(argc, argv);

#if defined _WIN32 || defined _WIN64
    winsock_startup();
#endif
    openssl_startup();
    openssl_thread_setup();

    test_tlsserver();

    openssl_thread_end();
    openssl_cleanup();

#if defined _WIN32 || defined _WIN64
    winsock_cleanup();
#endif

    _test_case.report();
    cmdline->help();
    return _test_case.result();
}
