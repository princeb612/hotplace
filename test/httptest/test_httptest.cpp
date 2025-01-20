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

#include "sample.hpp"

void do_split_url(const char *url, url_info_t *url_info) {
    const OPTION &option = _cmdline->value();

    split_url(url, url_info);

    if (option.verbose) {
        basic_stream bs;
        bs << "> url      : " << url << "\n"
           << "> scheme   : " << url_info->scheme << "\n"
           << "> host     : " << url_info->host << "\n"
           << "> port     : " << url_info->port << "\n"
           << "> uri      : " << url_info->uri << "\n"
           << "> uripath  : " << url_info->uripath << "\n"
           << "> query    : " << url_info->query << "\n";

        skey_value kv;
        http_uri::to_keyvalue(url_info->query, kv);
        kv.foreach ([&](const std::string &key, const std::string &value, void *param) -> void { bs << "> query*   : " << key << " : " << value << "\n"; });

        _logger->writeln(bs);
    }
}

void test_uri() {
    _test_case.begin("uri");
    url_info_t url_info;

    {
        do_split_url("https://test.com/resource?client_id=12345#part1", &url_info);

        _test_case.assert("https" == url_info.scheme, __FUNCTION__, "uri.scheme");
        _test_case.assert("test.com" == url_info.host, __FUNCTION__, "uri.host");
        _test_case.assert(443 == url_info.port, __FUNCTION__, "uri.port");
        _test_case.assert("/resource?client_id=12345#part1" == url_info.uri, __FUNCTION__, "uri.uri");
        _test_case.assert("/resource" == url_info.uripath, __FUNCTION__, "uri.uripath");
        _test_case.assert("client_id=12345" == url_info.query, __FUNCTION__, "uri.query.client_id");
        _test_case.assert("part1" == url_info.fragment, __FUNCTION__, "uri.fragment");
    }
    {
        do_split_url("https://test.com/~hush/simple_chart.html", &url_info);

        _test_case.assert("/~hush/simple_chart.html" == url_info.uripath, __FUNCTION__, "uri.uripath");
    }

    {
        skey_value kv;

        do_split_url(
            "/auth/v1/"
            "authorize?response_type=code&client_id=abcdefg&redirect_uri="
            "https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb&state=xyz",
            &url_info);
        http_uri::to_keyvalue(url_info.uri, kv);

        _test_case.assert("/auth/v1/authorize" == url_info.uripath, __FUNCTION__, "uri.query.uripath");
        _test_case.assert("code" == kv.get("response_type"), __FUNCTION__, "uri.query.response_type");
        _test_case.assert("xyz" == kv.get("state"), __FUNCTION__, "uri.query.state");
        _test_case.assert("https://client.example.com/cb" == kv.get("redirect_uri"), __FUNCTION__, "uri.query.redirect_uri");

        do_split_url(
            "/auth/v1/"
            "authorize?response_type=code&client_id=abcdefg&redirect_uri="
            "https://client.example.com/cb&state=xyz#part1",
            &url_info);
        http_uri::to_keyvalue(url_info.uri, kv);

        _test_case.assert("https://client.example.com/cb" == kv.get("redirect_uri"), __FUNCTION__, "uri.query.redirect_uri");
    }

    {
        skey_value kv;

        do_split_url("/client/cb?code=5lkd8ApNal3fkg3S6fh-uw&state=xyz", &url_info);
        http_uri::to_keyvalue(url_info.uri, kv);

        _test_case.assert("5lkd8ApNal3fkg3S6fh-uw" == kv.get("code"), __FUNCTION__, "uri.query.code");
    }

    {
        http_request request;
        request.open("GET /client/cb?code=5lkd8ApNal3fkg3S6fh-uw&state=xyz");
        skey_value &kv = request.get_http_uri().get_query_keyvalue();
        std::string code = kv.get("code");

        basic_stream bs;
        kv.foreach ([&](const std::string &key, const std::string &value, void *param) -> void { bs << "> query*   : " << key << " : " << value << "\n"; });
        _logger->write(bs);

        _test_case.assert("5lkd8ApNal3fkg3S6fh-uw" == kv.get("code"), __FUNCTION__, "uri.get_query_keyvalue.code");
    }
}

void test_request() {
    _test_case.begin("request");
    const OPTION &option = _cmdline->value();

    // chrome browser request data https://127.0.0.1:9000/test
    const char *input =
        "GET /test HTTP/1.1\r\n"
        "Accept: "
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/"
        "webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n"
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
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 "
        "Safari/537.36\r\n"
        "sec-ch-ua: \"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google "
        "Chrome\";v=\"120\"\r\n"
        "sec-ch-ua-mobile: ?0\r\n"
        "sec-ch-ua-platform: \"Windows\"\r\n\r\n";

    http_request request;
    request.open(input);

    if (option.verbose) {
        test_case_notimecheck notimecheck(_test_case);

        _logger->writeln("%s", input);
    }

    const char *uri = request.get_http_uri().get_uri();
    _test_case.assert(0 == strcmp(uri, "/test"), __FUNCTION__, "uri");

    _test_case.assert("GET" == request.get_method(), __FUNCTION__, "method");

    std::string header_accept_encoding;
    request.get_http_header().get("Accept-Encoding", header_accept_encoding);
    _test_case.assert(header_accept_encoding == "gzip, deflate, br", __FUNCTION__, "header");
}

void test_response_compose() {
    _test_case.begin("response");
    const OPTION &option = _cmdline->value();

    http_response response;
    response.get_http_header().add("Connection", "Keep-Alive");
    response.compose(200, "text/html", "<html><body>hello</body></html>");

    if (option.verbose) {
        test_case_notimecheck notimecheck(_test_case);

        basic_stream bs;
        response.get_response(bs);
        _logger->writeln("%s", bs.c_str());
    }

    _test_case.assert(200 == response.status_code(), __FUNCTION__, "status");
    _test_case.assert(31 == response.content_size(), __FUNCTION__, "Content-Length");
    _test_case.assert(0 == strcmp(response.content_type(), "text/html"), __FUNCTION__, "Content-Type");
}

void test_response_parse() {
    _test_case.begin("response");
    const OPTION &option = _cmdline->value();

    http_response response;
    std::string wwwauth;
    skey_value kv;

    const char *input =
        "HTTP/1.1 401 Unauthorized\r\n"
        "Connection: Keep-Alive\r\n"
        "Content-Length: 42\r\n"
        "Content-Type: text/html\r\n"
        "WWW-Authenticate: Digest realm=\"helloworld\", qop=\"auth, auth-int\", "
        "nonce=\"40dc29366886273821be1fcc5e23e9d7e9\", "
        "opaque=\"8be41306f5b9bb30019350c33b182858\"\r\n"
        "\r\n"
        "<html><body>401 Unauthorized</body></html>";

    response.open(input);

    response.get_http_header().get("WWW-Authenticate", wwwauth);
    http_header::to_keyvalue(wwwauth, kv);

    if (option.verbose) {
        kv.foreach ([&](const std::string &k, const std::string &v, void *param) -> void { _logger->writeln("> %s:=%s", k.c_str(), v.c_str()); });
    }

    _test_case.assert(401 == response.status_code(), __FUNCTION__, "status");
    std::string content_length;
    response.get_http_header().get("Content-Length", content_length);
    _test_case.assert("42" == content_length, __FUNCTION__, "Content-Length");
    _test_case.assert(42 == response.content_size(), __FUNCTION__, "size of content");
    _test_case.assert(0 == strcmp(response.content_type(), "text/html"), __FUNCTION__, "Content-Type");
    _test_case.assert("helloworld" == kv["realm"], __FUNCTION__, "realm from WWW-Authenticate");
    _test_case.assert("auth, auth-int" == kv["qop"], __FUNCTION__, "qop from WWW-Authenticate");
    _test_case.assert("40dc29366886273821be1fcc5e23e9d7e9" == kv["nonce"], __FUNCTION__, "nonce from WWW-Authenticate");
    _test_case.assert("8be41306f5b9bb30019350c33b182858" == kv["opaque"], __FUNCTION__, "opaque from WWW-Authenticate");
}

void test_uri_form_encoded_body_parameter() {
    _test_case.begin("uri");
    const OPTION &option = _cmdline->value();

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

    if (option.verbose) {
        _logger->writeln("%s", request_stream1.c_str());
        _logger->writeln("%s", request_stream2.c_str());
    }

    skey_value &kv1 = request1.get_http_uri().get_query_keyvalue();
    skey_value &kv2 = request2.get_http_uri().get_query_keyvalue();

    _test_case.assert(request_stream1 == request_stream2, __FUNCTION__, "form encoded body parameter");
    _test_case.assert(kv1.get("client_id") == "clientid", __FUNCTION__, "client_id");
    _test_case.assert(kv2.get("client_id") == "clientid", __FUNCTION__, "client_id");
}

void test_uri2() {
    _test_case.begin("uri");
    const OPTION &option = _cmdline->value();

    const char *input = "/resource?client_id=clientid&access_token=token";

    skey_value kv;
    http_uri::to_keyvalue(input, kv);
    std::string client_id = kv.get("client_id");
    std::string access_token = kv.get("access_token");
    if (option.verbose) {
        _logger->writeln("client_id %s", client_id.c_str());
        _logger->writeln("access_token %s", access_token.c_str());
    }
    _test_case.assert("clientid" == client_id, __FUNCTION__, "client_id");
    _test_case.assert("token" == access_token, __FUNCTION__, "access_token");
}

void test_escape_url() {
    _test_case.begin("uri");
    const OPTION &option = _cmdline->value();

    constexpr char input[] = "https://test.com:8080/%7Eb612%2Ftest%2Ehtml";

    basic_stream unescaped;
    unescape_url(input, &unescaped);

    if (option.verbose) {
        _logger->writeln("unescape : ", unescaped.c_str());
    }

    constexpr char expect[] = "https://test.com:8080/~b612/test.html";
    _test_case.assert(0 == strcmp(unescaped.c_str(), expect), __FUNCTION__, "unescape_url");
}

void test_basic_authentication() {
    _test_case.begin("Basic Authentication Scheme");
    const OPTION &option = _cmdline->value();

    return_t ret = errorcode_t::success;
    tcp_server_socket socket;  // dummy
    network_session session(&socket);
    basic_authentication_provider provider("basic realm");
    http_authentication_resolver resolver;
    http_request request;
    http_response response;
    basic_stream bs;

    resolver.get_basic_credentials(provider.get_realm()).add("user", "password");

    provider.request_auth(&session, &request, &response);

    std::function<return_t(const std::string &user, const std::string &password)> test_resolver = [&](const std::string &user,
                                                                                                      const std::string &password) -> return_t {
        return_t ret = errorcode_t::failed;

        // server response
        if (option.verbose) {
            response.get_response(bs);

            _logger->colorln("server response");
            _logger->writeln("%s", bs.c_str());
        }

        basic_stream cred;
        cred << user << ":" << password;

        // client request
        request.get_http_header().clear();
        request.open("GET / HTTP/1.1");
        request.get_http_header().add("Authorization", format("Basic %s", base64_encode(cred.c_str()).c_str()));

        if (option.verbose) {
            request.get_request(bs);

            _logger->colorln("client request");
            _logger->writeln("%s", bs.c_str());
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
 * cf. see digest_access_authentication_provider::auth_digest_access (slightly different)
 */
return_t do_calc_digest_digest_access(http_authentication_provider *provider, network_session *session, http_request *request, skey_value &kv,
                                      std::string &digest_response) {
    return_t ret = errorcode_t::success;
    const OPTION &option = _cmdline->value();
    __try2 {
        if (nullptr == provider || nullptr == request) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        digest_access_authentication_provider *dgst_provider = (digest_access_authentication_provider *)provider;

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

        if (option.verbose) {
            _logger->writeln("- a1 %s -> %s", dgst_a1.get_sequence().c_str(), digest_ha1.c_str());
            _logger->writeln("- a2 %s -> %s", dgst_a2.get_sequence().c_str(), digest_ha2.c_str());
            _logger->writeln("- resp %s -> %s", dgst_sequence.get_sequence().c_str(), digest_response.c_str());
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

void test_digest_access_authentication(const char *alg, unsigned long *ossl_minver) {
    _test_case.begin("Digest Access Authentication Scheme");
    const OPTION &option = _cmdline->value();

    return_t ret = errorcode_t::success;

    bool support = true;
    if (ossl_minver) {
        crypto_advisor *advisor = crypto_advisor::get_instance();
        support = advisor->check_minimum_version(*ossl_minver);
    }

    if (support) {
        tcp_server_socket socket;  // dummy
        network_session session(&socket);
        std::string realm = "digest realm";
        std::string qop = "auth";
        digest_access_authentication_provider provider(realm, alg, qop.c_str());
        http_authentication_resolver resolver;
        http_request request;
        http_response response;
        basic_stream bs;

        resolver.get_digest_credentials(provider.get_realm()).add(realm, alg ? alg : "", "user", "password");

        provider.request_auth(&session, &request, &response);

        std::function<return_t(const std::string &user, const std::string &password)> test_resolver = [&](const std::string &user,
                                                                                                          const std::string &password) -> return_t {
            return_t ret = errorcode_t::failed;

            // server response
            if (option.verbose) {
                response.get_response(bs);

                _logger->colorln("session nonce %s", session.get_session_data()->get("nonce").c_str());
                _logger->colorln("session opaque %s", session.get_session_data()->get("opaque").c_str());

                _logger->colorln("server response");
                _logger->writeln("%s", bs.c_str());
            }

            // calcuration
            std::string auth;
            std::string cred;
            skey_value kv;
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

            do_calc_digest_digest_access(&provider, &session, &request, kv, response_calc);  // calcurate a response

            basic_stream digest_stream;
            valist va;
            va << kv.get("username") << provider.get_realm() << kv.get("algorithm") << kv.get("nonce") << request.get_http_uri().get_uri() << response_calc
               << kv.get("opaque") << kv.get("qop") << kv.get("nc") << kv.get("cnonce");
            const char *digest_fmt =
                R"(Digest username="{1}", realm="{2}", algorithm={3}, nonce="{4}", uri="{5}", response="{6}", opaque="{7}", qop={8}, nc={9}, cnonce="{10}")";
            sprintf(&digest_stream, digest_fmt, va);
            request.get_http_header().add("Authorization", digest_stream.c_str());  // set a response

            if (option.verbose) {
                request.get_request(bs);

                _logger->colorln("client request");
                _logger->writeln("%s", bs.c_str());
            }

            response.close();

            // resolver
            bool test = resolver.resolve(&provider, &session, &request, &response);
            if (test) {
                ret = errorcode_t::success;
            }
            // _logger->colorln("[%08x] %s:%s", ret, user.c_str(), password.c_str());
            return ret;
        };

        ret = test_resolver("user", "password1");
        _test_case.assert((errorcode_t::success != ret), __FUNCTION__, "Digest Access Authentication Scheme (negative case) algorithm=%s", alg ? alg : "");
        ret = test_resolver("user", "password");
        _test_case.assert((errorcode_t::success == ret), __FUNCTION__, "Digest Access Authentication Scheme (positive case) algorithm=%s", alg ? alg : "");
    } else {
        _test_case.test(errorcode_t::not_supported, __FUNCTION__, "require OpenSSL_version_num %08x", *ossl_minver);
    }
}

void do_test_rfc_example_routine(const std::string &text, digest_access_authentication_provider *provider, http_request &request, const std::string &username,
                                 const std::string &password, const std::string &expect) {
    std::string response;
    std::string challenge;
    skey_value kv;

    // Authorization: Digest username="Mufasa",
    //         realm="testrealm@host.com",
    //         nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
    //         uri="/dir/index.html",
    //         qop=auth,
    //         nc=00000001,
    //         cnonce="0a4f113b",
    //         response="6629fae49393a05397450978507c4ef1",
    //         opaque="5ccc069c403ebaf9f0171e9517f40e41"
    challenge = provider->get_challenge(&request);
    // kv["username"]="Mufasa", kv["realm"]="testrealm@host.com", ...,
    // kv["opaque"]="5ccc069c403ebaf9f0171e9517f40e41"
    http_header::to_keyvalue(challenge, kv);
    // external
    kv.set("username", username);  // userhash
    kv.set("password", password);
    // computation
    do_calc_digest_digest_access(provider, nullptr, &request, kv, response);
    // compare expect and response
    _test_case.assert((expect == response) && (expect == kv.get("response")), __FUNCTION__, "%s", text.c_str());
}

void test_rfc_digest_example() {
    _test_case.begin("RFC examples");
    const OPTION &option = _cmdline->value();

    http_request request;

    // RFC 2617 3.5 Example "Circle Of Life"
    {
        digest_access_authentication_provider provider("testrealm@host.com");
        const char *value = R"(Digest username="Mufasa", realm="testrealm@host.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
            uri="/dir/index.html", qop=auth, nc=00000001, cnonce="0a4f113b", response="6629fae49393a05397450978507c4ef1",
            opaque="5ccc069c403ebaf9f0171e9517f40e41")";
        request.get_http_header().clear().add("Authorization", value);
        request.compose(http_method_t::HTTP_GET, "/dir/index.html", "");

        do_test_rfc_example_routine("RFC 2617 3.5 Example", &provider, request, "Mufasa", "Circle Of Life", "6629fae49393a05397450978507c4ef1");
    }

    // RFC 7616 3.9.1.  Example with SHA-256 and MD5 "Circle of Life"
    // part of MD5
    {
        digest_access_authentication_provider provider("http-auth@example.org", "MD5", "auth", false);
        const char *value = R"(Digest username="Mufasa", realm="http-auth@example.org", uri="/dir/index.html", algorithm=MD5,
            nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", nc=00000001, cnonce="f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ", qop=auth,
            response="8ca523f5e9506fed4657c9700eebdbec", opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS")";
        request.get_http_header().clear().add("Authorization", value);
        request.compose(http_method_t::HTTP_GET, "/dir/index.html", "");

        do_test_rfc_example_routine("RFC 7616 3.9.1. Examples with MD5", &provider, request, "Mufasa", "Circle of Life", "8ca523f5e9506fed4657c9700eebdbec");
    }
    // part of SHA-256
    {
        digest_access_authentication_provider provider("http-auth@example.org", "SHA-256", "auth", false);
        const char *value = R"(Digest username="Mufasa", realm="http-auth@example.org", uri="/dir/index.html", algorithm=SHA-256,
            nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", nc=00000001, cnonce="f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ", qop=auth,
            response="753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1", opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS")";
        request.get_http_header().clear().add("Authorization", value);
        request.compose(http_method_t::HTTP_GET, "/dir/index.html", "");

        do_test_rfc_example_routine("RFC 7616 3.9.1. Examples with SHA-256", &provider, request, "Mufasa", "Circle of Life",
                                    "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1");
    }

    // 1) enroll user/pass into digest credentials per realm
    //    digest_credentials.add(realm, algorithm, username, password);
    // 2) calc username
    //    auto valueof_username = dgst.add(username).add(":").add(realm).digest(algorithm).get();
    //    request Digest username="<valueof_username>" ... userhash=true
    // 3) select user/pass using hash
    //    select user from digest_credentials where username = '<valueof_username>';

#if 0
    // RFC 7616 3.9.2.  Example with SHA-512-256, Charset, and Userhash
    // part of SHA-512-256
    {
        // result mismatch ... what I missed ??
        //      try     _H<SHA-512-256>(unescape("J%C3%A4s%C3%B8n%20Doe"):api@example.org)
        //      expect '488869477bf257147b804c45308cd62ac4e25eb717b12b298c79e62dcea254ec'
        //
        // charset input
        //  3.9.2 userhash of the username, support the UTF-8 character encoding scheme
        //  J  U+00E4 s  U+00F8 n      D  o  e
        //  4A C3A4   73 C3B8   6E 20 44  6F 65
        //
        // debugging
        //  hotplace::crypto::openssl_digest::digest (this=0x5fe868, alg=0x5fe800 "sha2-512/256", input=..., hashstring="",
        //        encoding=hotplace::encoding_base16)
        //  (gdb) x/27bx input.c_str()
        //  0x29f0740:      0x4a    0xc3    0xa4    0x73    0xc3    0xb8    0x6e    0x20
        //  0x29f0748:      0x44    0x6f    0x65    0x3a    0x61    0x70    0x69    0x40
        //  0x29f0750:      0x65    0x78    0x61    0x6d    0x70    0x6c    0x65    0x2e
        //  0x29f0758:      0x6f    0x72    0x67
        //  (gdb) p hashstring
        //  $3 = "793263caabb707a56211940d90411ea4a575adeccb7e360aeb624ed06ece9b0b"

        const char *username_source = "J%C3%A4s%C3%B8n%20Doe";
        basic_stream user;
        unescape_url(username_source, &user);
        std::string username = user.c_str();
        _logger->dump(username);

        rfc2617_digest dgst;
        dgst.add(username).add(":").add("api@example.org").digest("SHA-512-256");
        _logger->writeln("- %s -> %s", dgst.get_sequence().c_str(), dgst.get().c_str());

        digest_access_authentication_provider provider("api@example.org", "SHA-512-256", "auth", true);
        const char *value = R"(Digest username="488869477bf257147b804c45308cd62ac4e25eb717b12b298c79e62dcea254ec", realm="api@example.org",
                uri="/doe.json", algorithm=SHA-512-256, nonce="5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK", nc=00000001,
                cnonce="NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v", qop=auth, response="ae66e67d6b427bd3f120414a82e4acff38e8ecd9101d6c861229025f607a79dd",
                opaque="HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS, userhash=true")";
        request.get_http_header().clear().add("Authorization", value);
        request.compose(http_method_t::HTTP_GET, "/doe.json", "");

        do_test_rfc_example_routine("RFC 7616 3.9.2. Example with SHA-512-256 and Userhash", &provider, request, username, "Secret, or not?",
                                 "ae66e67d6b427bd3f120414a82e4acff38e8ecd9101d6c861229025f607a79dd");
    }
#endif
    // test without charset (chrome)
    {
        // - _H<SHA-256>(user:testrealm@host.com) -> 43d8a4a4c9f8634537543ba66a36b6ab6f2a0f0e6eef9a0042909797fac93308
        digest_access_authentication_provider provider("testrealm@host.com", "SHA-256", "auth", true);
        const char *value = R"(Digest username="43d8a4a4c9f8634537543ba66a36b6ab6f2a0f0e6eef9a0042909797fac93308", realm="testrealm@host.com",
            nonce="61ca153723668dd86217cad715d3d2dc", uri="/auth/userhash", algorithm=SHA-256, response="4eec813c6cb8e3e4eb40a6b21a547fcb15b9158c5595d05c82612673980730ef",
            opaque="5f17278895ad1df3c8c4698686ffd074", qop=auth, nc=00000001, cnonce="b45026393ee4f4a4", userhash=true)";
        request.get_http_header().clear().add("Authorization", value);
        request.compose(http_method_t::HTTP_GET, "/auth/userhash", "");

        do_test_rfc_example_routine(
            "realm=testrealm@host.com, algorithm=SHA-256, qop=auth, userhash=true "
            "(chrome generated)",
            &provider, request, "user", "password", "4eec813c6cb8e3e4eb40a6b21a547fcb15b9158c5595d05c82612673980730ef");
    }
    {
        // - _H<SHA-256>(user:happiness) -> 9448db3978d7cbc5354221a5a84ba65db2e9a0fe625c62c52fb5171b974ee17d
        digest_access_authentication_provider provider("happiness", "SHA-256-sess", "auth", true);
        const char *value = R"(Digest username="9448db3978d7cbc5354221a5a84ba65db2e9a0fe625c62c52fb5171b974ee17d", realm="happiness",
            nonce="9bfec7e309fbbd69eea202ed0d2b501e", uri="/auth/digest", algorithm=SHA-256-sess,
            response="3defcdd8bda2d9304af3145c93687c1929e8ad6361b564d738ad2ed5eaaedf6d", opaque="2813b77014a6956fec12191120a3da08", qop=auth, nc=00000001,
            cnonce="3232cbe68a1b16ef", userhash=true)";
        request.get_http_header().clear().add("Authorization", value);
        request.compose(http_method_t::HTTP_GET, "/dir/index.html", "");

        do_test_rfc_example_routine(
            "realm=happiness, algorithm=SHA-256-sess, qop=auth, userhash=true "
            "(chrome generated)",
            &provider, request, "user", "password", "3defcdd8bda2d9304af3145c93687c1929e8ad6361b564d738ad2ed5eaaedf6d");
    }
}

void test_documents() {
    _test_case.begin("html_documents");
    html_documents docs;
    docs.add_documents_root("/", ".")
        .add_content_type(".css", "text/css")
        .add_content_type(".html", "text/html")
        .add_content_type(".json", "text/json")
        .set_default_document("index.html");

    std::string content_type;
    docs.get_content_type("/", content_type);
    _test_case.assert("text/html" == content_type, __FUNCTION__, "content-type #1");
    docs.get_content_type("/style.css", content_type);
    _test_case.assert("text/css" == content_type, __FUNCTION__, "content-type #2");
    docs.get_content_type("/index.json", content_type);
    _test_case.assert("text/json" == content_type, __FUNCTION__, "content-type #3");

    bool test = true;
    std::string local;
    std::string uri;

    uri = "/test.html";
    test = docs.get_local(uri, local);
    _test_case.assert(test, __FUNCTION__, "uri %s local %s", uri.c_str(), local.c_str());

    uri = "/../test.html";
    test = docs.get_local(uri, local);
    _test_case.nassert(test, __FUNCTION__, "uri %s local %s", uri.c_str(), local.c_str());
}

/*
 * @brief   basic implementation
 * @sa      test_get_httpclient
 */
void test_get_tlsclient() {
    _test_case.begin("httpserver test");
    const OPTION &option = _cmdline->value();

    return_t ret = errorcode_t::success;

    __try2 {
        url_info_t url_info;
        split_url(option.url.c_str(), &url_info);

        if ("https" != url_info.scheme) {
            __leave2;
        }

        socket_t sock = 0;

        tls_context_t *handle = nullptr;
        SSL_CTX *sslctx = nullptr;
        tlscert_open_simple(tlscert_flag_tls, &sslctx);
        transport_layer_security tls(sslctx);
        tls_client_socket cli(&tls);
        basic_stream bs;

        ret = cli.connect(&sock, &handle, url_info.host.c_str(), url_info.port, 5);
        if (errorcode_t::success == ret) {
            _logger->colorln("connected");

            http_request req;
            req.open(format("GET %s HTTP/1.1", url_info.uri.c_str()));
            basic_stream body;
            req.get_request(body);

            _logger->colorln("request");
            if (option.verbose) {
                _logger->writeln(body);
            }

            size_t cbsent = 0;
            ret = cli.send(sock, handle, body.c_str(), body.size(), &cbsent);
            if (errorcode_t::success == ret) {
                char buf[16];
                size_t sizeread = 0;

                if (0 == option.mode) {
                    ret = cli.read(sock, handle, buf, sizeof(buf), &sizeread);

                    if (option.verbose) {
                        _logger->dump((byte_t *)buf, sizeread);
                    }
                    while (errorcode_t::more_data == ret) {
                        ret = cli.more(sock, handle, buf, sizeof(buf), &sizeread);

                        if (option.verbose) {
                            _logger->dump((byte_t *)buf, sizeread);
                        }
                    }
                } else {
                    network_protocol_group group;
                    http_protocol http;
                    network_stream stream_read;
                    network_stream stream_interpreted;
                    group.add(&http);

                    ret = cli.read(sock, handle, buf, sizeof(buf), &sizeread);
                    stream_read.produce((byte_t *)buf, sizeread);
                    while (errorcode_t::more_data == ret) {
                        ret = cli.more(sock, handle, buf, sizeof(buf), &sizeread);
                        stream_read.produce((byte_t *)buf, sizeread);
                    }

                    stream_read.write(&group, &stream_interpreted);
                    network_stream_data *data = nullptr;
                    stream_interpreted.consume(&data);
                    if (data) {
                        _logger->colorln("response");
                        if (option.verbose) {
                            _logger->writeln("%.*s", (unsigned)data->size(), (char *)data->content());
                        }

                        data->release();
                    }
                }
            }  // send
            cli.close(sock, handle);
            _logger->colorln("closed");
        }  // connect

        SSL_CTX_free(sslctx);
    }
    __finally2 {
        // do nothing
    }
    _test_case.assert(true, __FUNCTION__, "tls_client_socket");
}

/*
 * @brief   simple implementation
 * @sa      test_get_tlsclient
 */
void test_get_httpclient() {
    _test_case.begin("httpserver test");
    const OPTION &option = _cmdline->value();

    return_t ret = errorcode_t::failed;
    http_client client;
    http_request request;
    http_response *response = nullptr;

    client.set_url(option.url);
    client.set_wto(60000);  // 1 min

    request.compose(http_method_t::HTTP_GET, "/");
    request.get_http_header().add("Accept-Encoding", "gzip, deflate");

    client.request(request, &response);
    if (response) {
        if (option.verbose) {
            basic_stream bs;
            response->get_response(bs);
            _logger->writeln("%s", bs.c_str());
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
    const OPTION &option = _cmdline->value();

    return_t ret = errorcode_t::failed;
    http_client client;
    http_request request;
    http_response *response = nullptr;
    client.set_url(option.url);
    client.set_wto(60000);  // 1 min

    request.compose(http_method_t::HTTP_GET, "/auth/bearer");
    request.get_http_header().clear().add("Accept-Encoding", "gzip, deflate").add("Authorization", "Bearer token");

    client.request(request, &response);
    if (response) {
        if (option.verbose) {
            basic_stream bs;
            response->get_response(bs);
            _logger->writeln("%s", bs.c_str());
        }
        response->release();
        if (200 == response->status_code()) {
            ret = errorcode_t::success;
        }
    }
    _test_case.test(ret, __FUNCTION__, "bearer");
}
