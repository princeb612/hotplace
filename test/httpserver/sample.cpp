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

void api_test_handler(network_session*, http_request* request, http_response* response) {
    response->compose(200, "text/html", "<html><body>page - ok<body></html>");
}
void api_v1_test_handler(network_session*, http_request* request, http_response* response) {
    response->compose(200, "application/json", "{\"result\":\"ok\"}");
}

t_shared_instance<http_router> _http_router;

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

    /* route */
    t_shared_instance<http_router> router = _http_router;

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
                    router->route(session, &request, &response);
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
    network_server netserver;
    network_multiplexer_context_t* handle_http_ipv4 = nullptr;
    network_multiplexer_context_t* handle_http_ipv6 = nullptr;
    network_multiplexer_context_t* handle_https_ipv4 = nullptr;
    network_multiplexer_context_t* handle_https_ipv6 = nullptr;

    FILE* fp = fopen(FILENAME_RUN, "w");

    fclose(fp);

    http_protocol* http_prot = nullptr;
    server_socket svr_sock;
    transport_layer_security* tls = nullptr;
    transport_layer_security_server* tls_server = nullptr;

    // part of ssl certificate
    x509cert cert("server.crt", "server.key");
    cert.set_cipher_list("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_8_SHA256:TLS_AES_128_CCM_SHA256")
        .set_verify(0);

    __try2 {
        // Basic Authentication (realm)
        std::string basic_realm = "Hello World";
        // Digest Access Authentication (realm/algorithm/qop/userhash)
        std::string digest_access_realm = "happiness";
        std::string digest_access_alg = "SHA-256-sess";
        std::string digest_access_qop = "auth";
        bool digest_access_userhash = true;
        // Bearer Authentication (realm)
        std::string bearer_realm = "hotplace";
        // OAuth 2.0 (realm)
        std::string oauth2_realm = "somewhere over the rainbow";

        /* route */
        _http_router.make_share(new http_router);

        std::function<void(network_session*, http_request*, http_response*)> default_handler = [&](network_session* session, http_request* request,
                                                                                                   http_response* response) -> void {
            basic_stream bs;
            request->get_request(bs);
            response->compose(200, "text/html", "<html><body><pre>%s</pre></body></html>", bs.c_str());
        };
        std::function<void(network_session*, http_request*, http_response*)> error_handler = [&](network_session* session, http_request* request,
                                                                                                 http_response* response) -> void {
            basic_stream bs;
            request->get_request(bs);
            response->compose(200, "text/html", "<html><body>404 Not Found<pre>%s</pre></body></html>", bs.c_str());
        };

        std::function<void(network_session*, http_request*, http_response*)> weblogin_handler = [&](network_session* session, http_request* request,
                                                                                                    http_response* response) -> void {
            // studying RFC 6749

            // resource server
            //      create an app
            //      - [out] app id
            //      - [in] valid domain, redirect_uri, permission (query email)
            //      validate, test, review and then publish
            //
            // client
            //      RFC 6749 4.1.1.  Authorization Request

            basic_stream req;
            openssl_prng prng;
            std::string state;
            state = prng.nonce(16);
            std::string auth_server = "https://localhost:9000";
            std::string auth_uri = "/auth/authorize";
            std::string client_id = "12345";
            std::string redirect_uri = "https://localhost:9000/auth/cb";
            req << auth_server << auth_uri << "?response_type=code&client_id=" << client_id << "&redirect_uri=" << redirect_uri << "&state=" << state;
            response->get_http_header().add("Location", req.c_str());
            response->compose(302);
        };
        std::function<void(network_session*, http_request*, http_response*)> auth_handler = [&](network_session* session, http_request* request,
                                                                                                http_response* response) -> void {
            // studying RFC 6749

            // this uri authenticated

            // login
            //      RFC 6749 4.1.2.  Authorization Response
            //          HTTP/1.1 302 Found
            //          Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA

            key_value& kv = request->get_http_uri().get_query_keyvalue();

            std::string response_type = kv.get("response_type");
            std::string client_id = kv.get("client_id");
            std::string redirect_uri = kv.get("redirect_uri");
            std::string state = kv.get("state");
            std::string code;

            openssl_prng prng;
            code = prng.nonce(16);

            basic_stream resp;
            resp << redirect_uri << "?code=" << code << "&state=" << state;
            response->get_http_header().add("Location", resp.c_str());
            response->compose(302);

            session->get_session_data()->set("state", state);
        };
        std::function<void(network_session*, http_request*, http_response*)> cb_handler = [&](network_session* session, http_request* request,
                                                                                              http_response* response) -> void {
            // studying RFC 6749

            key_value& kv = request->get_http_uri().get_query_keyvalue();
            std::string code = kv.get("code");
            std::string state = kv.get("state");

            if (state == session->get_session_data()->get("state")) {
                //      RFC 6749 4.1.3.  Access Token Request

                http_request req;
                basic_stream req_content;
                std::string token_uri = "https://localhost:9000/auth/token";
                std::string redirect_uri = "https://localhost:9000/auth/cb";

                req_content << "grant_type=authorization_code&code=" << code << "&redirect_uri=" << redirect_uri;
                req.get_http_header()
                    .add("Authorization", format("Basic %s", base64_encode("user:password").c_str()))
                    .add("Content-Type", "application/x-www-form-urlencoded");
                req.compose(http_method_t::HTTP_POST, token_uri, req_content.c_str());

                // make a request
                basic_stream bs;
                http_client client;
                client.set_ttl(10000);
                http_response* resp = nullptr;
                client.request(req, &resp);
                if (resp) {
                    req.get_request(bs);
                    printf("%s\n", bs.c_str());
                    resp->get_response(bs);
                    printf("%s\n", bs.c_str());
                    *response = *resp;
                    resp->release();
                } else {
                    printf("error\n");

                    // temporary response
                    req.get_request(bs);
                    response->compose(200, "text/html", "<html><body><pre>%s</pre></body></html>", bs.c_str());
                }
            } else {
                response->compose(200, "text/html", "<html><body>invalid_request</body></html>");
            }
        };
        std::function<void(network_session*, http_request*, http_response*)> token_handler = [&](network_session* session, http_request* request,
                                                                                                 http_response* response) -> void {
            basic_stream bs;
            request->get_request(bs);
            printf("token\n%s\n", bs.c_str());
            response->compose(200, "text/plain", "token");
        };

        (*_http_router)
            .get_html_documents()
            .add_documents_root("/", ".")
            .add_content_type(".html", "text/html")
            .add_content_type(".json", "text/json")
            .set_default_document("index.html");

        (*_http_router)
            // http_router
            .add("/api/test", api_test_handler)
            .add("/api/v1/test", api_v1_test_handler)
            .add("/test", default_handler)
            .add(404, error_handler)
            // basic authentication
            .add("/auth/basic", default_handler)
            .add("/auth/basic", new basic_authentication_provider(basic_realm.c_str()))
            // digest access authentication
            .add("/auth/digest", default_handler)
            .add("/auth/digest", new digest_access_authentication_provider(digest_access_realm.c_str(), digest_access_alg.c_str(), digest_access_qop.c_str(),
                                                                           digest_access_userhash))
            // bearer authentication
            .add("/auth/bearer", default_handler)
            .add("/auth/bearer", new bearer_authentication_provider(bearer_realm.c_str()))
            // studying RFC 6749
            .add("/auth/weblogin", weblogin_handler)
            .add("/auth/authorize", auth_handler)
            .add("/auth/authorize", new digest_access_authentication_provider(digest_access_realm.c_str(), digest_access_alg.c_str(), digest_access_qop.c_str(),
                                                                              digest_access_userhash))
            .add("/auth/cb", cb_handler)
            .add("/auth/token", token_handler)
            .add("/auth/token", new basic_authentication_provider(basic_realm.c_str()));

        // simple implementation
        (*_http_router)
            .get_authenticate_resolver()
            // builtin basic_resolver, digest_resolver, bearer_resolver
            .basic_credential(base64_encode("user:password"))
            .digest_access_credential(digest_access_realm, digest_access_alg, "user", "password")
            .bearer_credential("clientid", "token")
            // basic_resolver, digest_resolver, bearer_resolver if necessary
            // .basic_resolver([&](http_authenticate_provider* provider, network_session* session, http_request* request, http_response* response) -> bool {
            //    /* ... */ })
            // .digest_resolver([&](http_authenticate_provider* provider, network_session* session, http_request* request, http_response* response) -> bool {
            //    /* ... */ })
            // .bearer_resolver([&](http_authenticate_provider* provider, network_session* session, http_request* request, http_response* response) -> bool {
            //    /* ... */ })
            ;

        /* server */
        __try_new_catch(tls, new transport_layer_security(cert.get()), ret, __leave2);
        __try_new_catch(http_prot, new http_protocol, ret, __leave2);
        __try_new_catch(tls_server, new transport_layer_security_server(tls), ret, __leave2);

        http_prot->set_constraints(protocol_constraints_t::protocol_packet_size, 1 << 12);  // constraints maximum packet size to 4KB

        // start server
        netserver.open(&handle_http_ipv4, AF_INET, IPPROTO_TCP, option.port, 32000, network_routine, nullptr, &svr_sock);
        netserver.open(&handle_http_ipv6, AF_INET6, IPPROTO_TCP, option.port, 32000, network_routine, nullptr, &svr_sock);
        netserver.open(&handle_https_ipv4, AF_INET, IPPROTO_TCP, option.port_tls, 32000, network_routine, nullptr, tls_server);
        netserver.open(&handle_https_ipv6, AF_INET6, IPPROTO_TCP, option.port_tls, 32000, network_routine, nullptr, tls_server);
        netserver.add_protocol(handle_http_ipv4, http_prot);
        netserver.add_protocol(handle_http_ipv6, http_prot);
        netserver.add_protocol(handle_https_ipv4, http_prot);
        netserver.add_protocol(handle_https_ipv6, http_prot);

        netserver.consumer_loop_run(handle_http_ipv4, 2);
        netserver.consumer_loop_run(handle_http_ipv6, 2);
        netserver.consumer_loop_run(handle_https_ipv4, 2);
        netserver.consumer_loop_run(handle_https_ipv6, 2);
        netserver.event_loop_run(handle_http_ipv4, 2);
        netserver.event_loop_run(handle_http_ipv6, 2);
        netserver.event_loop_run(handle_https_ipv4, 2);
        netserver.event_loop_run(handle_https_ipv6, 2);

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

        netserver.event_loop_break(handle_http_ipv4, 2);
        netserver.event_loop_break(handle_http_ipv6, 2);
        netserver.event_loop_break(handle_https_ipv4, 2);
        netserver.event_loop_break(handle_https_ipv6, 2);
        netserver.consumer_loop_break(handle_http_ipv4, 2);
        netserver.consumer_loop_break(handle_http_ipv6, 2);
        netserver.consumer_loop_break(handle_https_ipv4, 2);
        netserver.consumer_loop_break(handle_https_ipv6, 2);
    }
    __finally2 {
        netserver.close(handle_http_ipv4);
        netserver.close(handle_http_ipv6);
        netserver.close(handle_https_ipv4);
        netserver.close(handle_https_ipv6);

        http_prot->release();
        tls_server->release();
        tls->release();
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
