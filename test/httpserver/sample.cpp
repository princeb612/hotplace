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

void api_test_handler(http_request* request, http_response* response) { response->compose(200, "text/html", "<html><body>page - ok<body></html>"); }
void api_v1_test_handler(http_request* request, http_response* response) { response->compose(200, "application/json", "{\"result\":\"ok\"}"); }

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

                    std::cout << "uri : " << request.get_uri() << std::endl;
                    std::cout << "method : " << request.get_method() << std::endl;

                    /* URI, URL, query */
                    http_uri& uri = request.get_http_uri();
                    for (size_t i = 0; i < uri.countof_query(); i++) {
                        std::string key;
                        std::string value;
                        uri.query(i, key, value);
                        std::cout << key.c_str() << " -> " << value.c_str() << std::endl;
                    }

                    std::cout << "tls : " << use_tls << std::endl;

                    /* header */
                    request.get_http_header().get("Accept-Encoding", encoding);
                    std::cout << "encoding : " << encoding.c_str() << std::endl << std::endl;
                }

                if (use_tls) {
                    // using http_router
                    router->route(request.get_uri(), session, &request, &response);
                    response.get_response(bs);
                } else {
                    // handle wo http_router
                    response.compose(200, "text/html", "<html><body>%s<pre>%s</pre></body></html>", request.get_uri(), bs.c_str());
                }

                if (option.debug) {
                    cprint("send %i", session_socket->client_socket);
                    basic_stream resp;
                    response.get_response(resp);
                    basic_stream temp;
                    dump_memory(resp, &temp);
                    printf("%s\n", temp.c_str());
                }

                session->send((const char*)bs.data(), bs.size());
                fflush(stdout);
            }

            break;
        case mux_disconnect:
            std::cout << "disconnect " << session_socket->client_socket << std::endl;
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

    SSL_CTX* x509 = nullptr;
    http_protocol* http_prot = nullptr;
    server_socket svr_sock;
    transport_layer_security* tls = nullptr;
    transport_layer_security_server* tls_server = nullptr;

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

        // part of ssl certificate
        ret = x509_open(&x509, "server.crt", "server.key");
        _test_case.test(ret, __FUNCTION__, "x509");

        SSL_CTX_set_cipher_list(x509,
                                "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_8_SHA256:TLS_AES_128_CCM_SHA256");
        // SSL_CTX_set_cipher_list (x509,
        // "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:AES128-GCM-SHA256:AES128-SHA256:AES256-GCM-SHA384:AES256-SHA256:!aNULL:!eNULL:!LOW:!EXP:!RC4");
        SSL_CTX_set_verify(x509, 0, nullptr);

        rfc2617_digest dgst;
        std::set<std::string> basic_credentials;
        basic_credentials.insert(base64_encode("user:password"));

        typedef struct _userhash_data {
            std::string username;
            std::string password;
        } userhash_data;
        std::map<std::string, std::string> digest_access_credentials;
        std::map<std::string, userhash_data> digest_access_userhash_credentials;
        digest_access_credentials.insert(std::make_pair("user", "password"));  // userhash=false
        userhash_data userdata = {"user", "password"};
        dgst.clear().add("user").add(":").add(digest_access_realm).digest(digest_access_alg);
        digest_access_userhash_credentials.insert(std::make_pair(dgst.get(), userdata));  // userhash=true

        std::map<std::string, std::string> bearer_credentials;
        bearer_credentials.insert(std::make_pair("s6BhdRkqt3", "7Fjfp0ZBr1KtDRbnfVdmIw"));  // client_id, client_secret

        /* route */
        _http_router.make_share(new http_router);

        std::function<void(http_request*, http_response*)> default_handler = [&](http_request* request, http_response* response) -> void {
            basic_stream bs;
            request->get_request(bs);
            response->compose(200, "text/html", "<html><body><pre>%s</pre></body></html>", bs.c_str());
        };

        (*_http_router)
            .add("/api/test", api_test_handler)
            .add("/api/v1/test", api_v1_test_handler)
#if __cplusplus >= 201402L  // c++14
            .add("/test",
                 [&](http_request* request, http_response* response) -> void {
                     basic_stream bs;
                     request->get_request(bs);
                     response->compose(200, "text/html", "<html><body>request %s<br><pre>%s</pre></body></html>", request->get_uri(), bs.c_str());
                 })
#else
            .add("/test", default_handler)  // gcc 4.8
#endif
            .add("/auth/basic", default_handler)
            .add("/auth/digest", default_handler)
            .add("/auth/bearer", default_handler)
            .add("/auth/oauth2", default_handler)
            .add(404, default_handler)
            .add("/auth/basic", new http_basic_authenticate_provider(basic_realm.c_str()))
            .add("/auth/digest", new http_digest_access_authenticate_provider(digest_access_realm.c_str(), digest_access_alg.c_str(), digest_access_qop.c_str(),
                                                                              digest_access_userhash))
            .add("/auth/bearer", new http_bearer_authenticate_provider(bearer_realm.c_str()))
            .add("/auth/oauth2", new oauth2_provider(oauth2_realm.c_str()));

        // simple implementation
        (*_http_router)
            .get_authenticate_resolver()
            .basic_resolver([&](http_authenticate_provider* provider, network_session* session, http_request* request, http_response* response) -> bool {
                std::string challenge = provider->get_challenge(request);

                size_t pos = 0;
                tokenize(challenge, " ", pos);                           // Basic
                std::string credential = tokenize(challenge, " ", pos);  // base64(user:password)

                std::set<std::string>::iterator iter = basic_credentials.find(credential);
                bool ret_value = (basic_credentials.end() != iter);
                return ret_value;
            })
            .digest_resolver([&](http_authenticate_provider* provider, network_session* session, http_request* request, http_response* response) -> bool {
                bool ret_value = false;
                return_t ret = errorcode_t::success;
                http_digest_access_authenticate_provider* digest_provider = (http_digest_access_authenticate_provider*)provider;
                key_value kv;

                ret = digest_provider->prepare_digest_access(session, request, response, kv);
                if (errorcode_t::success == ret) {
                    // get username from kv.get("username"), and then read password (cache, in-memory db)
                    // and then call provider->auth_digest_access
                    std::string username = kv.get("username");
                    std::string password;
                    bool found = false;
                    if (digest_access_userhash) {
                        std::map<std::string, userhash_data>::iterator iter = digest_access_userhash_credentials.find(username);
                        if (digest_access_userhash_credentials.end() != iter) {
                            found = true;
                            kv.set("username", iter->second.username);
                            password = iter->second.password;
                        }
                    } else {
                        std::map<std::string, std::string>::iterator iter = digest_access_credentials.find(username);
                        if (digest_access_credentials.end() != iter) {
                            found = true;
                            password = iter->second;
                        }
                    }
                    if (found) {
                        kv.set("password", password);
                        ret = digest_provider->auth_digest_access(session, request, response, kv);
                        if (errorcode_t::success == ret) {
                            ret_value = true;
                        }
                    }
                }

                return ret_value;
            })
            .bearer_resolver([&](http_authenticate_provider* provider, network_session* session, http_request* request, http_response* response) -> bool {
                bool ret_value = false;
                std::string challenge = provider->get_challenge(request);
                std::string token;

                if (0 == strncmp("Bearer", challenge.c_str(), 6)) {
                    size_t pos = 6;
                    token = tokenize(challenge, " ", pos);
                    if (token == session->get_session_data()->get("access_token")) {
                        ret_value = true;
                    }
                } else {
                    key_value kv;
                    http_uri::to_keyvalue(challenge, kv);
                    token = kv.get("access_token");
                    std::string client_id = kv.get("client_id");
                    std::string client_secret = kv.get("client_secret");
                    std::map<std::string, std::string>::iterator iter = bearer_credentials.find(client_id);
                    if (iter != bearer_credentials.end()) {
                        session->get_session_data()->set("bearer", "access_token");  // hmm... I need something grace
                    }
                }

                return ret_value;
            })
            .oauth2_resolver([&](http_authenticate_provider* provider, network_session* session, http_request* request, http_response* response) -> bool {
                bool ret_value = false;
                std::string challenge = provider->get_challenge(request);
                std::string token;

                if (0 == strncmp("Bearer", challenge.c_str(), 6)) {
                    size_t pos = 6;
                    token = tokenize(challenge, " ", pos);
                    if (token == session->get_session_data()->get("access_token")) {
                        ret_value = true;
                    }
                } else {
                    key_value kv;
                    http_uri::to_keyvalue(challenge, kv);
                    token = kv.get("access_token");
                    std::string client_id = kv.get("client_id");
                    std::string client_secret = kv.get("client_secret");
                    std::map<std::string, std::string>::iterator iter = bearer_credentials.find(client_id);
                    if (iter != bearer_credentials.end()) {
                        session->get_session_data()->set("bearer", "access_token");  // hmm... I need something grace
                    }
                }

                return ret_value;
            });

        /* server */
        __try_new_catch(tls, new transport_layer_security(x509), ret, __leave2);
        __try_new_catch(http_prot, new http_protocol, ret, __leave2);
        __try_new_catch(tls_server, new transport_layer_security_server(tls), ret, __leave2);

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
        SSL_CTX_free(x509);
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
