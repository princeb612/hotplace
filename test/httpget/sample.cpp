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
    int connect;
    int debug;

    _OPTION() : url("https://localhost:9000/"), mode(0), connect(0), debug(0) {}
} OPTION;

t_shared_instance<cmdline_t<OPTION> > cmdline;

void cprint(const char* text, ...) {
    console_color _concolor;

    std::cout << _concolor.turnon().set_fgcolor(console_color_t::cyan);
    va_list ap;
    va_start(ap, text);
    vprintf(text, ap);
    va_end(ap);
    std::cout << _concolor.turnoff() << std::endl;
}

void test_request() {
    _test_case.begin("request");
    // chrome browser request data https://127.0.0.1:9000/test
    const char* input =
        "GET /test HTTP/1.1\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n"
        "Accept-Encoding: gzip, deflate, br\r\n"
        "Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7\r\n"
        "Cache-Control: max-age=0\r\n"
        "Connection: keep-alive\r\n"
        "Content-Length: 2\r\n"
        "Host: 127.0.0.1:9000\r\n"
        "Sec-Fetch-Dest: document\r\n"
        "Sec-Fetch-Mode: navigate\r\n"
        "Sec-Fetch-Site: none\r\n"
        "Sec-Fetch-User: ?1\r\n"
        "Upgrade-Insecure-Requests: 1\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"
        "sec-ch-ua: \"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"\r\n"
        "sec-ch-ua-mobile: ?0\r\n"
        "sec-ch-ua-platform: \"Windows\"\r\n\r\n";

    http_request request;
    request.open(input);

    OPTION& option = cmdline->value();
    if (option.debug) {
        test_case_notimecheck notimecheck(_test_case);

        printf("%s\n", input);
    }

    const char* uri = request.get_uri();
    _test_case.assert(0 == strcmp(uri, "/test"), __FUNCTION__, "uri");

    const char* method = request.get_method();
    _test_case.assert(0 == strcmp(method, "GET"), __FUNCTION__, "method");

    std::string header_accept_encoding;
    request.get_http_header().get("Accept-Encoding", header_accept_encoding);
    _test_case.assert(header_accept_encoding == "gzip, deflate, br", __FUNCTION__, "header");
}

void test_response_compose() {
    _test_case.begin("response.compose");

    http_response response;
    response.get_http_header().add("Connection", "Keep-Alive");
    response.compose(200, "text/html", "<html><body>hello</body></html>");

    OPTION& option = cmdline->value();
    if (option.debug) {
        test_case_notimecheck notimecheck(_test_case);

        basic_stream bs;
        response.get_response(bs);
        printf("%s\n", bs.c_str());
    }

    _test_case.assert(200 == response.status_code(), __FUNCTION__, "status");
    _test_case.assert(31 == response.content_size(), __FUNCTION__, "Content-Length");
    _test_case.assert(0 == strcmp(response.content_type(), "text/html"), __FUNCTION__, "Content-Type");
}

void test_response_parse() {
    _test_case.begin("response.open");
    OPTION& option = cmdline->value();

    http_response response;
    std::string wwwauth;
    key_value kv;

    const char* input =
        "HTTP/1.1 401 Unauthorized\r\n"
        "Connection: Keep-Alive\r\n"
        "Content-Length: 42\r\n"
        "Content-Type: text/html\r\n"
        "WWW-Authenticate: Digest realm=\"helloworld\", qop=\"auth, auth-int\", nonce=\"40dc29366886273821be1fcc5e23e9d7e9\", "
        "opaque=\"8be41306f5b9bb30019350c33b182858\"\r\n"
        "\r\n"
        "<html><body>401 Unauthorized</body></html>";

    response.open(input);

    response.get_http_header().get("WWW-Authenticate", wwwauth);
    http_header::to_keyvalue(wwwauth, kv);

    if (option.debug) {
        kv.foreach ([&](std::string const& k, std::string const& v, void* param) -> void { printf("> %s:=%s\n", k.c_str(), v.c_str()); });
    }

    _test_case.assert(401 == response.status_code(), __FUNCTION__, "status");
    std::string content_length;
    response.get_http_header().get("Content-Length", content_length);
    _test_case.assert("42" == content_length, __FUNCTION__, "Content-Length");
    _test_case.assert(42 == response.content_size(), __FUNCTION__, "size of content");
    _test_case.assert(0 == strcmp(response.content_type(), "text/html"), __FUNCTION__, "Content-Type");
    _test_case.assert(0 == strcmp("helloworld", kv["realm"]), __FUNCTION__, "realm from WWW-Authenticate");
    _test_case.assert(0 == strcmp("auth, auth-int", kv["qop"]), __FUNCTION__, "qop from WWW-Authenticate");
    _test_case.assert(0 == strcmp("40dc29366886273821be1fcc5e23e9d7e9", kv["nonce"]), __FUNCTION__, "nonce from WWW-Authenticate");
    _test_case.assert(0 == strcmp("8be41306f5b9bb30019350c33b182858", kv["opaque"]), __FUNCTION__, "opaque from WWW-Authenticate");
}

void test_uri_form_encoded_body_parameter() {
    _test_case.begin("form encoded body parameter");
    http_request request1;
    http_request request2;
    basic_stream request_stream1;
    basic_stream request_stream2;

    request1.compose(http_method_t::HTTP_GET, "/auth/bearer?client_id=s6BhdRkqt3&client_secret=7Fjfp0ZBr1KtDRbnfVdmIw", "");  // reform if body is empty
    request1.get_http_header().add("Accept-Encoding", "gzip, deflate");
    request1.get_request(request_stream1);

    // another way
    request2.compose(http_method_t::HTTP_GET, "/auth/bearer", "client_id=s6BhdRkqt3&client_secret=7Fjfp0ZBr1KtDRbnfVdmIw");
    request2.get_http_header().add("Content-Type", "application/x-www-form-urlencoded").add("Accept-Encoding", "gzip, deflate");
    request2.get_request(request_stream2);

    OPTION& option = cmdline->value();

    if (option.debug) {
        printf("%s\n", request_stream1.c_str());
        printf("%s\n", request_stream2.c_str());
    }

    _test_case.assert(request_stream1 == request_stream2, __FUNCTION__, "form encoded body parameter");
}

void test_uri(const char* input) {
    _test_case.begin("uri");
    OPTION& option = cmdline->value();

    key_value kv;
    http_uri::to_keyvalue(input, kv);
    std::string client_id = kv.get("client_id");
    std::string client_secret = kv.get("client_secret");
    if (option.debug) {
        printf("client_id %s\n", client_id.c_str());
        printf("client_secret %s\n", client_secret.c_str());
    }
    _test_case.assert("s6BhdRkqt3" == client_id, __FUNCTION__, "client_id");
    _test_case.assert("7Fjfp0ZBr1KtDRbnfVdmIw" == client_secret, __FUNCTION__, "client_secret");
}

void test_basic_authenticate() {
    _test_case.begin("Basic Authentication Scheme");
    return_t ret = errorcode_t::success;
    server_socket socket;  // dummy
    network_session session(&socket);
    http_basic_authenticate_provider provider("basic realm");
    http_authenticate_resolver resolver;
    http_request request;
    http_response response;
    basic_stream bs;

    OPTION& option = cmdline->value();

    resolver.basic_resolver([&](http_authenticate_provider* provider, network_session* session, http_request* request, http_response* response) -> bool {
        bool test = false;
        std::string challenge = provider->get_challenge(request);

        size_t pos = 0;
        tokenize(challenge, " ", pos);                           // Basic
        std::string credential = tokenize(challenge, " ", pos);  // base64(user:password)

        test = (credential == base64_encode("user:password"));
        return test;
    });

    provider.request_auth(&session, &request, &response);

    std::function<return_t(std::string const& user, std::string const& password)> test_resolver = [&](std::string const& user,
                                                                                                      std::string const& password) -> return_t {
        return_t ret = errorcode_t::failed;

        // server response
        if (option.debug) {
            response.get_response(bs);

            cprint("server response");
            printf("%s\n", bs.c_str());
        }

        basic_stream cred;
        cred << user << ":" << password;

        // client request
        request.open("GET / HTTP/1.1");
        request.get_http_header().add("Authorization", format("Basic %s", base64_encode(cred.c_str()).c_str()));

        if (option.debug) {
            request.get_request(bs);

            cprint("client request");
            printf("%s\n", bs.c_str());
        }

        response.close();

        // resolver
        bool test = resolver.resolve(&provider, &session, &request, &response);
        if (test) {
            ret = errorcode_t::success;
        }
        return ret;
    };

    ret = test_resolver("user", "password");
    _test_case.assert((errorcode_t::success == ret), __FUNCTION__, "Basic Authentication Scheme (positive case)");
    ret = test_resolver("user", "password1");
    _test_case.assert((errorcode_t::success != ret), __FUNCTION__, "Basic Authentication Scheme (negative case)");
}

/**
 * calcuration routine
 * cf. see http_digest_access_authenticate_provider::auth_digest_access (slightly diffrent)
 */
return_t calc_digest_digest_access(http_authenticate_provider* provider, network_session* session, http_request* request, key_value& kv,
                                   std::string& digest_response) {
    return_t ret = errorcode_t::success;
    OPTION& option = cmdline->value();
    __try2 {
        if (nullptr == session || nullptr == request) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        http_digest_access_authenticate_provider* dgst_provider = (http_digest_access_authenticate_provider*)provider;

        std::string alg;
        std::string hashalg = dgst_provider->get_algorithm();
        std::string qop;

        alg = kv.get("algorithm");
        qop = kv.get("qop");

        rfc2617_digest dgst_a1;
        rfc2617_digest dgst_a2;
        rfc2617_digest dgst_sequence;
        std::string digest_ha1;
        std::string digest_ha2;

        // RFC 2617 3.2.2.2 A1
        dgst_a1.clear().add(kv.get("username")).add(":").add(provider->get_realm()).add(":").add(kv.get("password")).digest(hashalg);
        if (ends_with(alg, "-sess")) {
            digest_ha1 = dgst_a1.add(":").add(kv.get("nonce")).add(":").add(kv.get("cnonce")).digest(hashalg).get();
        } else {
            digest_ha1 = dgst_a1.get();
        }

        // RFC 2617 3.2.2.3 A2
        // If the qop parameter's value is "auth" or is unspecified
        //      A2       = Method ":" digest-uri-value
        // If the qop value is "auth-int"
        //      A2       = Method ":" digest-uri-value ":" H(entity-body)
        dgst_a2.clear().add(request->get_method()).add(":").add(kv.get("uri"));
        if ("auth-int" == qop) {
            // RFC 2616 Hypertext Transfer Protocol -- HTTP/1.1
            // 7.2 Entity Body
            basic_stream entity_body(request->get_content().c_str());
            rfc2617_digest entity_dgst;
            entity_dgst.add(entity_body).digest(hashalg);
            dgst_a2.add(":").add(entity_dgst.get());
        }
        digest_ha2 = dgst_a2.digest(hashalg).get();

        // RFC 2617 3.2.2.1 Request-Digest
        // RFC 7616 3.4.1.  Response
        //      If the qop value is "auth" or "auth-int":
        //          request-digest  = <"> < KD ( H(A1),     unq(nonce-value)
        //                                              ":" nc-value
        //                                              ":" unq(cnonce-value)
        //                                              ":" unq(qop-value)
        //                                              ":" H(A2)
        //                                      ) <">
        //
        //      If the "qop" directive is not present
        //          request-digest  =
        //             <"> < KD ( H(A1), unq(nonce-value) ":" H(A2) ) >
        //             <">

        // std::string digest_response;
        dgst_sequence.clear().add(digest_ha1).add(":").add(kv.get("nonce"));
        if (("auth" == qop) || ("auth-int" == qop)) {
            dgst_sequence.add(":").add(kv.get("nc")).add(":").add(kv.get("cnonce")).add(":").add(kv.get("qop"));
        }
        dgst_sequence.add(":").add(digest_ha2);
        digest_response = dgst_sequence.digest(hashalg).get();

        if (option.debug) {
            printf("- a1 %s -> %s\n", dgst_a1.get_sequence().c_str(), digest_ha1.c_str());
            printf("- a2 %s -> %s\n", dgst_a2.get_sequence().c_str(), digest_ha2.c_str());
            printf("- resp %s -> %s\n", dgst_sequence.get_sequence().c_str(), digest_response.c_str());
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

void test_digest_access_authenticate(const char* alg = nullptr) {
    _test_case.begin("Digest Access Authentication Scheme");
    return_t ret = errorcode_t::success;
    server_socket socket;  // dummy
    network_session session(&socket);
    http_digest_access_authenticate_provider provider("digest realm", alg, "auth");
    http_authenticate_resolver resolver;
    http_request request;
    http_response response;
    basic_stream bs;

    OPTION& option = cmdline->value();

    resolver.digest_resolver([&](http_authenticate_provider* provider, network_session* session, http_request* request, http_response* response) -> bool {
        bool ret_value = false;
        return_t ret = errorcode_t::success;
        http_digest_access_authenticate_provider* digest_provider = (http_digest_access_authenticate_provider*)provider;
        key_value kv;

        ret = digest_provider->prepare_digest_access(session, request, response, kv);  // update (key, value)
        cprint("[%08x] prepare_digest_access", ret);
        if (errorcode_t::success == ret) {
            // get username from kv.get("username"), and then read password (cache, in-memory db)
            kv.set("password", "password");

            if (option.debug) {
                printf("* session opaque:=%s\n", session->get_session_data()->get("opaque").c_str());
                kv.foreach ([&](std::string const& k, std::string const& v, void* param) -> void { printf("> %s:=%s\n", k.c_str(), v.c_str()); });
            }

            // and then call provider->auth_digest_access
            return_t ret = digest_provider->auth_digest_access(session, request, response, kv);
            if (errorcode_t::success == ret) {
                ret_value = true;
            }
        }

        return ret_value;
    });

    provider.request_auth(&session, &request, &response);

    std::function<return_t(std::string const& user, std::string const& password)> test_resolver = [&](std::string const& user,
                                                                                                      std::string const& password) -> return_t {
        return_t ret = errorcode_t::failed;

        // server response
        if (option.debug) {
            response.get_response(bs);

            cprint("session nonce %s", session.get_session_data()->get("nonce").c_str());
            cprint("session opaque %s", session.get_session_data()->get("opaque").c_str());

            cprint("server response");
            printf("%s\n", bs.c_str());
        }

        // calcuration
        std::string auth;
        std::string cred;
        key_value kv;
        size_t pos = 0;
        response.get_http_header().get("WWW-Authenticate", auth);
        http_header::to_keyvalue(auth, kv);

        std::string response_calc;
        kv.set("username", user);
        kv.set("password", password);  // calc
        kv.set("qop", "auth");
        kv.set("nc", "00000002");
        kv.set("cnonce", "0123456789abcdef");
        if (kv.get("algorithm").empty()) {
            kv.set("algorithm", "MD5");  // calc
        }

        // client request
        request.open("GET /auth/digest HTTP/1.1");  // set a method and an uri
        kv.set("uri", request.get_uri());

        calc_digest_digest_access(&provider, &session, &request, kv, response_calc);  // calcurate a response
        request.get_http_header().add(
            "Authorization",
            format("Digest username=\"%s\", realm=\"%s\", algorithm=%s, nonce=\"%s\", uri=\"%s\", response=\"%s\", opaque=\"%s\", qop=%s, nc=%s, cnonce=\"%s\"",
                   kv.get("username").c_str(), provider.get_realm().c_str(), kv.get("algorithm").c_str(), kv.get("nonce").c_str(), request.get_uri(),
                   response_calc.c_str(), kv.get("opaque").c_str(), kv.get("qop").c_str(), kv.get("nc").c_str(), kv.get("cnonce").c_str()));  // set a response

        if (option.debug) {
            request.get_request(bs);

            cprint("client request");
            printf("%s\n", bs.c_str());
        }

        response.close();

        // resolver
        bool test = resolver.resolve(&provider, &session, &request, &response);
        if (test) {
            ret = errorcode_t::success;
        }
        cprint("[%08x] %s:%s", ret, user.c_str(), password.c_str());
        return ret;
    };

    ret = test_resolver("user", "password1");
    _test_case.assert((errorcode_t::success != ret), __FUNCTION__, "Digest Access Authentication Scheme (negative case) algorithm=%s", alg ? alg : "");
    ret = test_resolver("user", "password");
    _test_case.assert((errorcode_t::success == ret), __FUNCTION__, "Digest Access Authentication Scheme (positive case) algorithm=%s", alg ? alg : "");
}

void test_get() {
    _test_case.begin("get");
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
        basic_stream bs;

        ret = cli.connect(&sock, &handle, url_info.host.c_str(), url_info.port, 5);
        if (errorcode_t::success == ret) {
            cprint("connected");

            http_request req;
            req.open(format("GET %s HTTP/1.1", url_info.uri.c_str()));
            basic_stream body;
            req.get_request(body);

            cprint("request");
            if (option.debug) {
                std::cout << body.c_str() << std::endl;
            }

            size_t cbsent = 0;
            ret = cli.send(sock, handle, body.c_str(), body.size(), &cbsent);
            if (errorcode_t::success == ret) {
                char buf[16];
                size_t sizeread = 0;

                if (0 == option.mode) {
                    ret = cli.read(sock, handle, buf, sizeof(buf), &sizeread);

                    if (option.debug) {
                        dump_memory((byte_t*)buf, sizeread, &bs);
                        printf("%s\n", bs.c_str());
                    }
                    while (errorcode_t::more_data == ret) {
                        ret = cli.more(sock, handle, buf, sizeof(buf), &sizeread);

                        if (option.debug) {
                            dump_memory((byte_t*)buf, sizeread, &bs);
                            printf("%s\n", bs.c_str());
                        }
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
                        cprint("response");
                        if (option.debug) {
                            printf("%.*s\n", (unsigned)data->size(), (char*)data->content());
                        }

                        data->release();
                    }
                }
            }  // send
            cli.close(sock, handle);
            cprint("closed");
        }  // connect

        SSL_CTX_free(x509);
    }
    __finally2 {
        // do nothing
    }
}

void test_client() {
    _test_case.begin("client");
    OPTION& option = cmdline->value();

    // see test/http_server

    http_client client;
    http_response* response = nullptr;

    cprint("https");
    client.set_ttl(60000);  // 1 min
    client.request("https://localhost:9000/api/test?access_token=mF_9.B5f-4.1JqM", &response);
    if (response) {
        if (option.debug) {
            basic_stream bs;
            response->get_response(bs);
            printf("%s\n", bs.c_str());
        }
        response->release();
    }

    // RFC 6750 2.2.  Form-Encoded Body Parameter
    // RFC 6750 4.  Example Access Token Response (implement http_bearer_authenticate_provider)
    cprint("client_id+client_secret");
    http_request request;
    int status_code = 0;
    basic_stream stream;
    request.compose(http_method_t::HTTP_GET, "/auth/bearer?client_id=s6BhdRkqt3&client_secret=7Fjfp0ZBr1KtDRbnfVdmIw", "");  // reform if body is empty
    request.get_http_header().add("Accept-Encoding", "gzip, deflate");
    client.request(request, &response);
    if (response) {
        status_code = response->status_code();
        stream << response->content();

        if (option.debug) {
            basic_stream bs;
            response->get_response(bs);
            printf("%s\n", bs.c_str());
        }
        response->release();
    }

    if (200 == status_code) {
        // json
        std::string access_token;

        json_t* json_root = nullptr;
        json_open_stream(&json_root, stream.c_str());
        if (json_root) {
            const char* unp_access_token = nullptr;
            const char* unp_token_type = nullptr;
            json_unpack(json_root, "{s:s}", "access_token", &unp_access_token);
            json_unpack(json_root, "{s:s}", "token_type", &unp_token_type);

            if (unp_access_token && (0 == strcmp("Bearer", unp_token_type))) {
                access_token = unp_access_token;
            }

            json_decref(json_root);
        }

        // Bearer
        cprint("access_token");
        request.compose(http_method_t::HTTP_GET, "/auth/bearer", "");
        request.get_http_header().add("Authorization", format("Bearer %s", access_token.c_str()));
        client.request(request, &response);
        if (response) {
            if (option.debug) {
                basic_stream bs;
                response->get_response(bs);
                printf("%s\n", bs.c_str());
            }
            response->release();
        }
    } else if (401 == status_code) {
        //
    } else {
        //
    }

    _test_case.assert(200 == status_code, __FUNCTION__, "Bearer Authentication");
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

    *cmdline << cmdarg_t<OPTION>("-c", "connect", [&](OPTION& o, char* param) -> void { o.connect = 1; }).optional()
             << cmdarg_t<OPTION>("-p", "read stream using http_protocol", [&](OPTION& o, char* param) -> void { o.mode = 1; }).optional()
             << cmdarg_t<OPTION>("-d", "debug", [&](OPTION& o, char* param) -> void { o.debug = 1; }).optional()
             << cmdarg_t<OPTION>("-u", "url (default https://localhost:9000/)", [&](OPTION& o, char* param) -> void { o.url = param; }).preced().optional();

    cmdline->parse(argc, argv);
    OPTION& option = cmdline->value();

    // request
    test_request();

    // response
    test_response_compose();
    test_response_parse();

    // authenticate
    test_basic_authenticate();
    test_digest_access_authenticate();
    test_digest_access_authenticate("MD5");
    test_digest_access_authenticate("MD5-sess");
    test_digest_access_authenticate("SHA-256");
    test_digest_access_authenticate("SHA-256-sess");
    test_digest_access_authenticate("SHA-512-256");
    test_digest_access_authenticate("SHA-512-256-sess");

    // uri
    test_uri_form_encoded_body_parameter();
    const char* input1 = "/resource?client_id=s6BhdRkqt3&client_secret=7Fjfp0ZBr1KtDRbnfVdmIw";
    const char* input2 = "/resource?client_id=s6BhdRkqt3&client_secret=7Fjfp0ZBr1KtDRbnfVdmIw";
    test_uri(input1);
    test_uri(input2);

    // network test
    if (option.connect) {
        // how to test
        // terminal 1
        //   cd hotplace
        //   ./make.sh debug pch
        //   cd build/test/httpserver
        //   ./test-httpserver -d
        // terminal 2
        //   cd build/test/httpget
        //   ./test-httpget -d -c
        test_get();
        test_client();
    }

    openssl_thread_end();
    openssl_cleanup();

#if defined _WIN32 || defined _WIN64
    winsock_cleanup();
#endif

    _test_case.report(5);
    cmdline->help();
    return _test_case.result();
}
