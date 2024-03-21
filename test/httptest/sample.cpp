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

void do_split_url(const char* url, url_info_t* url_info) {
    OPTION& option = cmdline->value();

    split_url(url, url_info);

    if (option.debug) {
        basic_stream bs;
        bs << "> url      : " << url << "\n"
           << "> scheme   : " << url_info->scheme << "\n"
           << "> host     : " << url_info->host << "\n"
           << "> port     : " << url_info->port << "\n"
           << "> uri      : " << url_info->uri << "\n"
           << "> uripath  : " << url_info->uripath << "\n"
           << "> query    : " << url_info->query << "\n";

        key_value kv;
        http_uri::to_keyvalue(url_info->query, kv);
        kv.foreach ([&](std::string const& key, std::string const& value, void* param) -> void { bs << "> query*   : " << key << " : " << value << "\n"; });

        std::cout << bs.c_str();
    }
}

void test_uri() {
    _test_case.begin("uri");
    url_info_t url_info;

    do_split_url("https://test.com/resource?client_id=12345#part1", &url_info);

    _test_case.assert("https" == url_info.scheme, __FUNCTION__, "uri.scheme");
    _test_case.assert("test.com" == url_info.host, __FUNCTION__, "uri.host");
    _test_case.assert(443 == url_info.port, __FUNCTION__, "uri.port");
    _test_case.assert("/resource?client_id=12345#part1" == url_info.uri, __FUNCTION__, "uri.uri");
    _test_case.assert("/resource" == url_info.uripath, __FUNCTION__, "uri.uripath");
    _test_case.assert("client_id=12345" == url_info.query, __FUNCTION__, "uri.query");
    _test_case.assert("part1" == url_info.fragment, __FUNCTION__, "uri.fragment");

    key_value kv;

    do_split_url("/auth/v1/authorize?response_type=code&client_id=abcdefg&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb&state=xyz", &url_info);
    http_uri::to_keyvalue(url_info.uri, kv);

    _test_case.assert("/auth/v1/authorize" == url_info.uripath, __FUNCTION__, "query.uripath");
    _test_case.assert("code" == kv.get("response_type"), __FUNCTION__, "query.response_type");
    _test_case.assert("xyz" == kv.get("state"), __FUNCTION__, "query.state");
    _test_case.assert("https://client.example.com/cb" == kv.get("redirect_uri"), __FUNCTION__, "query.redirect_uri");

    do_split_url("/auth/v1/authorize?response_type=code&client_id=abcdefg&redirect_uri=https://client.example.com/cb&state=xyz#part1", &url_info);
    http_uri::to_keyvalue(url_info.uri, kv);

    _test_case.assert("https://client.example.com/cb" == kv.get("redirect_uri"), __FUNCTION__, "query");
}

void test_request() {
    _test_case.begin("request");
    OPTION& option = cmdline->value();

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

    if (option.debug) {
        test_case_notimecheck notimecheck(_test_case);

        printf("%s\n", input);
    }

    const char* uri = request.get_http_uri().get_uri();
    _test_case.assert(0 == strcmp(uri, "/test"), __FUNCTION__, "uri");

    const char* method = request.get_method();
    _test_case.assert(0 == strcmp(method, "GET"), __FUNCTION__, "method");

    std::string header_accept_encoding;
    request.get_http_header().get("Accept-Encoding", header_accept_encoding);
    _test_case.assert(header_accept_encoding == "gzip, deflate, br", __FUNCTION__, "header");
}

void test_response_compose() {
    _test_case.begin("response");
    OPTION& option = cmdline->value();

    http_response response;
    response.get_http_header().add("Connection", "Keep-Alive");
    response.compose(200, "text/html", "<html><body>hello</body></html>");

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
    _test_case.begin("response");
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
    _test_case.begin("uri");
    OPTION& option = cmdline->value();

    http_request request1;
    http_request request2;
    basic_stream request_stream1;
    basic_stream request_stream2;

    request1.compose(http_method_t::HTTP_GET, "/auth/bearer?client_id=clientid", "");  // reform if body is empty
    request1.get_http_header().add("Accept-Encoding", "gzip, deflate");
    request1.get_request(request_stream1);

    // another way
    request2.get_http_header().clear().add("Content-Type", "application/x-www-form-urlencoded").add("Accept-Encoding", "gzip, deflate");
    request2.compose(http_method_t::HTTP_GET, "/auth/bearer", "client_id=clientid");
    request2.get_request(request_stream2);

    if (option.debug) {
        printf("%s\n", request_stream1.c_str());
        printf("%s\n", request_stream2.c_str());
    }

    _test_case.assert(request_stream1 == request_stream2, __FUNCTION__, "form encoded body parameter");
}

void test_uri2() {
    _test_case.begin("uri");
    OPTION& option = cmdline->value();

    const char* input = "/resource?client_id=clientid&access_token=token";

    key_value kv;
    http_uri::to_keyvalue(input, kv);
    std::string client_id = kv.get("client_id");
    std::string access_token = kv.get("access_token");
    if (option.debug) {
        printf("client_id %s\n", client_id.c_str());
        printf("access_token %s\n", access_token.c_str());
    }
    _test_case.assert("clientid" == client_id, __FUNCTION__, "client_id");
    _test_case.assert("token" == access_token, __FUNCTION__, "access_token");
}

void test_escape_url() {
    _test_case.begin("uri");
    OPTION& option = cmdline->value();

    constexpr char input[] = "https://test.com:8080/%7Eb612%2Ftest%2Ehtml";

    basic_stream unescaped;
    unescape_url(input, &unescaped);

    if (option.debug) {
        std::cout << "unescape : " << unescaped.c_str() << std::endl;
    }

    constexpr char expect[] = "https://test.com:8080/~b612/test.html";
    _test_case.assert(0 == strcmp(unescaped.c_str(), expect), __FUNCTION__, "unescape_url");
}

void test_basic_authentication() {
    _test_case.begin("Basic Authentication Scheme");
    OPTION& option = cmdline->value();

    return_t ret = errorcode_t::success;
    server_socket socket;  // dummy
    network_session session(&socket);
    basic_authentication_provider provider("basic realm");
    http_authentication_resolver resolver;
    http_request request;
    http_response response;
    basic_stream bs;

    resolver.get_basic_credentials().add("user", "password");

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
        request.get_http_header().clear();
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
 * cf. see digest_access_authentication_provider::auth_digest_access (slightly diffrent)
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

        digest_access_authentication_provider* dgst_provider = (digest_access_authentication_provider*)provider;

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

void test_digest_access_authentication(const char* alg = nullptr) {
    _test_case.begin("Digest Access Authentication Scheme");
    OPTION& option = cmdline->value();

    return_t ret = errorcode_t::success;
    server_socket socket;  // dummy
    network_session session(&socket);
    std::string realm = "digest realm";
    std::string qop = "auth";
    digest_access_authentication_provider provider(realm, alg, qop.c_str());
    http_authentication_resolver resolver;
    http_request request;
    http_response response;
    basic_stream bs;

    resolver.get_digest_credentials().add(realm, alg ? alg : "", "user", "password");

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
        request.get_http_header().clear();
        request.open("GET /auth/digest HTTP/1.1");  // set a method and an uri
        kv.set("uri", request.get_http_uri().get_uri());

        calc_digest_digest_access(&provider, &session, &request, kv, response_calc);  // calcurate a response
        request.get_http_header().add(
            "Authorization",
            format("Digest username=\"%s\", realm=\"%s\", algorithm=%s, nonce=\"%s\", uri=\"%s\", response=\"%s\", opaque=\"%s\", qop=%s, nc=%s, cnonce=\"%s\"",
                   kv.get("username").c_str(), provider.get_realm().c_str(), kv.get("algorithm").c_str(), kv.get("nonce").c_str(),
                   request.get_http_uri().get_uri(), response_calc.c_str(), kv.get("opaque").c_str(), kv.get("qop").c_str(), kv.get("nc").c_str(),
                   kv.get("cnonce").c_str()));  // set a response

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

/*
 * @brief   basic implementation
 * @sa      test_get_httpclient
 */
void test_get_tlsclient() {
    _test_case.begin("httpserver test");
    OPTION& option = cmdline->value();

    return_t ret = errorcode_t::success;

    __try2 {
        url_info_t url_info;
        split_url(option.url.c_str(), &url_info);

        if ("https" != url_info.scheme) {
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
    _test_case.assert(true, __FUNCTION__, "transport_layer_security_client");
}

/*
 * @brief   simple implementation
 * @sa      test_get_tlsclient
 */
void test_get_httpclient() {
    _test_case.begin("httpserver test");
    OPTION& option = cmdline->value();

    return_t ret = errorcode_t::failed;
    http_client client;
    http_request request;
    http_response* response = nullptr;

    client.set_url(option.url);
    client.set_ttl(60000);  // 1 min

    request.compose(http_method_t::HTTP_GET, "/");
    request.get_http_header().add("Accept-Encoding", "gzip, deflate");

    client.request(request, &response);
    if (response) {
        if (option.debug) {
            basic_stream bs;
            response->get_response(bs);
            printf("%s\n", bs.c_str());
        }
        response->release();
        if (200 == response->status_code()) {
            ret = errorcode_t::success;
        }
    }
    _test_case.test(ret, __FUNCTION__, "http_client");
}

void test_bearer_token() {
    _test_case.begin("httpserver test");
    OPTION& option = cmdline->value();

    return_t ret = errorcode_t::failed;
    http_client client;
    http_request request;
    http_response* response = nullptr;
    client.set_url(option.url);
    client.set_ttl(60000);  // 1 min

    request.compose(http_method_t::HTTP_GET, "/auth/bearer");
    request.get_http_header().clear().add("Accept-Encoding", "gzip, deflate").add("Authorization", "Bearer token");

    client.request(request, &response);
    if (response) {
        if (option.debug) {
            basic_stream bs;
            response->get_response(bs);
            printf("%s\n", bs.c_str());
        }
        response->release();
        if (200 == response->status_code()) {
            ret = errorcode_t::success;
        }
    }
    _test_case.test(ret, __FUNCTION__, "bearer");
}

void test_rfc6749_authorizationcode() {
    _test_case.begin("oauth2");
    OPTION& option = cmdline->value();

    return_t ret = errorcode_t::failed;
    http_client client;
    http_request request;
    http_response* response = nullptr;
    client.set_url(option.url);
    client.set_ttl(60000);  // 1 min

    request.compose(http_method_t::HTTP_GET, "/authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz&redirect_uri=https%3A%2F%2Flocalhost%2Fcb");

    client.request(request, &response);
    if (response) {
        if (option.debug) {
            basic_stream bs;
            response->get_response(bs);
            printf("%s\n", bs.c_str());
        }
        response->release();
        if (302 == response->status_code()) {
            ret = errorcode_t::success;
        }
    }
    _test_case.test(ret, __FUNCTION__, "oauth2");
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

    // uri
    test_uri();
    test_uri_form_encoded_body_parameter();
    test_uri2();
    test_escape_url();

    // request
    test_request();

    // response
    test_response_compose();
    test_response_parse();

    // authenticate
    test_basic_authentication();
    test_digest_access_authentication();
    test_digest_access_authentication("MD5");
    test_digest_access_authentication("MD5-sess");
    test_digest_access_authentication("SHA-256");
    test_digest_access_authentication("SHA-256-sess");
    test_digest_access_authentication("SHA-512-256");
    test_digest_access_authentication("SHA-512-256-sess");

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
        test_get_tlsclient();
        test_get_httpclient();

        test_bearer_token();
        test_rfc6749_authorizationcode();
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
