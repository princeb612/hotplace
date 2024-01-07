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

#define FILENAME_RUN _T (".run")

typedef struct _OPTION {
    int port;
    int port_tls;
    int debug;

    _OPTION() : port(80), port_tls(9000), debug(0) {}
} OPTION;

t_shared_instance<cmdline_t<OPTION> > cmdline;

void api_test_handler(http_request* request, http_response* response) { response->compose(200, "text/html", "<html><body>page - ok<body></html>"); }
void api_v1_test_handler(http_request* request, http_response* response) { response->compose(200, "application/json", "{\"result\":\"ok\"}"); }

t_shared_instance<http_router> _http_router;

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
            std::cout << "connect " << session_socket->client_socket << std::endl;
            break;
        case mux_read:
            printf("read %i (%zi) %.*s\n", session_socket->client_socket, bufsize, (unsigned)bufsize, buf);
            {
                arch_t use_tls = 0;
                session->get_server_socket()->query(server_socket_query_t::query_support_tls, &use_tls);

                http_request request;
                http_response response(&request);
                basic_stream bs;
                request.open(buf, bufsize);

                if (option.debug) {
                    dump_memory((unsigned char*)buf, bufsize, &bs, 32);
                    printf("%s\n", bs.c_str());

                    std::string encoding;
                    http_header* header = request.get_header();

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
                    header->get("Accept-Encoding", encoding);
                    std::cout << "encoding : " << encoding.c_str() << std::endl << std::endl;
                }

                if (use_tls) {
                    ret = router->route(request.get_uri(), session, &request, &response);
                    if (errorcode_t::success != ret) {
                        response.compose(404, "text/html", "<html><body>page not found %s</body></html>", request.get_uri());
                    }
                    response.get_response(bs);
                } else {
                    // RFC 2817 4. Server Requested Upgrade to HTTP over TLS
                    http_header* resp_header = response.get_header();
                    resp_header->add("Upgrade", "TLS/1.2, HTTP/1.1");
                    resp_header->add("Connection", "Upgrade");
                    response.compose(426, "text/html", "<html><body>Upgrade %s</body></html>", request.get_uri()).get_response(bs);
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
        // part of ssl certificate
        ret = x509_open(&x509, "server.crt", "server.key");
        _test_case.test(ret, __FUNCTION__, "x509");

        SSL_CTX_set_cipher_list(x509,
                                "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_8_SHA256:TLS_AES_128_CCM_SHA256");
        // SSL_CTX_set_cipher_list (x509,
        // "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:AES128-GCM-SHA256:AES128-SHA256:AES256-GCM-SHA384:AES256-SHA256:!aNULL:!eNULL:!LOW:!EXP:!RC4");
        SSL_CTX_set_verify(x509, 0, nullptr);

        std::set<std::string> basic_credentials;
        basic_credentials.insert(base64_encode("user:password"));
        std::map<std::string, std::string> digest_access_credentials;
        digest_access_credentials.insert(std::make_pair("user", "password"));

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
            .add("/test",
                 [&](http_request* request, http_response* response) -> void {
                     basic_stream bs;
                     request->get_request(bs);
                     response->compose(200, "text/html", "<html><body>request %s<br><pre>%s</pre></body></html>", request->get_uri(), bs.c_str());
                 })
            .add("/auth/basic", default_handler)
            //.add("/auth/digest", default_handler)
            //.add("/auth/bearer", default_handler)
            .add("/auth/basic", new http_basic_authenticate_provider("Hello World"))
            //.add("/auth/digest", new http_digest_access_authenticate_provider("happiness"))
            //.add("/auth/bearer", new http_digest_access_authenticate_provider("hotplace"))
            ;

        (*_http_router)
            .get_authenticate_resolver()
            .basic_resolver([&](http_authenticate_provider* provider, network_session* session, http_request* request, std::string credential) -> bool {
                // simple implementation (using file, database, ...)
                std::set<std::string>::iterator iter = basic_credentials.find(credential);
                bool ret_value = (basic_credentials.end() != iter);
                return ret_value;
            })
            .digest_resolver([&](http_authenticate_provider* provider, network_session* session, http_request* request, std::string credential) -> bool {
                // simple implementation (using file, database, ...)
                bool ret_value = false;
                std::string opaque_session;
                session->get_session_data()->query("opaque", opaque_session);

                if (false == opaque_session.empty()) {
                    key_value kv;
                    http_header::to_keyvalue(credential, kv);

                    std::string alg;
                    std::string hashalg = "md5";  // default
                    std::string username;
                    std::string password;
                    std::string opaque;
                    std::string response;

                    opaque = kv.get("opaque");
                    if (opaque == opaque_session) {
                        alg = kv.get("algorithm");
                        username = kv.get("username");
                        response = kv.get("response");

                        std::map<std::string, std::string>::iterator iter = digest_access_credentials.find(username);
                        if (digest_access_credentials.end() != iter) {
                            password = iter->second;
                        }

                        openssl_digest dgst;

                        // RFC 2617 3.2.2.1 Request-Digest
                        // RFC 7616 3.4.1.  Response
                        //      If the qop value is "auth" or "auth-int":
                        //          response = <"> < KD ( H(A1), unq(nonce)
                        //                                       ":" nc
                        //                                       ":" unq(cnonce)
                        //                                       ":" unq(qop)
                        //                                       ":" H(A2)
                        //                              ) <">
                        // RFC 7616
                        //      MD5, SHA-512-256, SHA-256
                        //      MD5-sess, SHA-512-256-sess, SHA-256-sess
                        std::map<std::string, std::string> algmap;
                        algmap.insert(std::make_pair("MD5", "md5"));
                        algmap.insert(std::make_pair("MD5-sess", "md5"));
                        algmap.insert(std::make_pair("SHA-512-256", "sha2-512/256"));
                        algmap.insert(std::make_pair("SHA-512-256-sess", "sha2-512/256"));
                        algmap.insert(std::make_pair("SHA-256", "sha256"));
                        algmap.insert(std::make_pair("SHA-256-sess", "sha256"));

                        if (alg.size()) {
                            std::map<std::string, std::string>::iterator alg_iter = algmap.find(alg);
                            if (algmap.end() != alg_iter) {
                                hashalg = alg_iter->second;
                            }
                        }

                        std::string digest_ha1;
                        std::string digest_ha2;

                        // RFC 2617 3.2.2.2 A1
                        basic_stream stream_a1;
                        stream_a1 << username << ":" << provider->get_realm() << ":" << password;
                        dgst.digest(hashalg.c_str(), stream_a1, digest_ha1);

                        if (ends_with(alg, "-sess")) {
                            basic_stream stream_sess_a1;
                            stream_sess_a1 << digest_ha1 << ":" << kv.get("nonce") << ":" << kv.get("cnonce");
                            dgst.digest(hashalg.c_str(), stream_sess_a1, digest_ha1);
                        }

                        // RFC 2617 3.2.2.3 A2
                        basic_stream stream_a2;
                        stream_a2 << request->get_method() << ":" << kv.get("uri");
                        if ("auth-int" == kv.get("qop")) {
                            crypto_advisor* advisor = crypto_advisor::get_instance();
                            binary_t bin;
                            const hint_digest_t* hint = advisor->hintof_digest(hashalg.c_str());
                            if (hint) {
                                bin.resize(hint->digest_size);
                            }
                            stream_a2 << ":";
                            stream_a2.write(&bin[0], bin.size());
                        }
                        dgst.digest(hashalg.c_str(), stream_a2, digest_ha2);

                        // RFC 2617 3.2.2.1 Request-Digest
                        basic_stream sequence;
                        std::string digest_response;
                        sequence << digest_ha1 << ":" << kv.get("nonce") << ":" << kv.get("nc") << ":" << kv.get("cnonce") << ":" << kv.get("qop") << ":"
                                 << digest_ha2;
                        dgst.digest(hashalg.c_str(), sequence, digest_response);

                        printf(">>> %s => %s\n", stream_a1.c_str(), digest_ha1.c_str());
                        printf(">>> %s => %s\n", stream_a2.c_str(), digest_ha1.c_str());
                        printf(">>> %s => %s\n", sequence.c_str(), digest_response.c_str());
                        printf(">>> %s %s\n", response.c_str(), digest_response.c_str());

                        ret_value = (digest_response == response);
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
