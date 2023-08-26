/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *      simple https server implementation
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/sdk.hpp>
#include <stdio.h>
#include <iostream>
#include <signal.h>

using namespace hotplace;
using namespace hotplace::io;
using namespace hotplace::crypto;
using namespace hotplace::net;

test_case _test_case;

#define FILENAME_RUN _T (".run")
#define PORT 9000

typedef return_t (*http_handler_t)(const char* method, const char* uri, const char* action, const char* request,
                                   http_response* response);
typedef std::map<std::string, http_handler_t> handler_http_handlers_t;
typedef std::pair<handler_http_handlers_t::iterator, bool> handler_http_handlers_pib_t;

class http_handler_http_handlers
{
public:
    http_handler_http_handlers ();
    ~http_handler_http_handlers ();

    return_t add (const char* uri, http_handler_t handler);
    http_handler_t find (const char* uri);
protected:
    handler_http_handlers_t _http_handlers;
};

http_handler_http_handlers::http_handler_http_handlers ()
{
    // do nothing
}

http_handler_http_handlers::~http_handler_http_handlers ()
{
    // do nothing
}

return_t http_handler_http_handlers::add (const char* uri, http_handler_t handler)
{
    return_t ret = errorcode_t::success;
    handler_http_handlers_pib_t pib = _http_handlers.insert (std::make_pair (uri, handler));

    if (false == pib.second) {
        ret = errorcode_t::already_exist;
    }
    return ret;
}
http_handler_t http_handler_http_handlers::find (const char* uri)
{
    http_handler_t handler = nullptr;
    handler_http_handlers_t::iterator iter = _http_handlers.find (std::string (uri));

    if (_http_handlers.end () != iter) {
        handler = iter->second;
    }
    return handler;
}
// end of http_handler_http_handlers

// sample handler
return_t api_test_handler (const char* method, const char* uri, const char* action, const char* request,
                           http_response* response)
{
    response->compose ("text/html", "<html><body>page - ok<body></html>", 200);
    return 0;
}
return_t api_v1_test_handler (const char* method, const char* uri, const char* action, const char* request,
                              http_response* response)
{
    response->compose ("application/json", "{\"result\":\"ok\"}", 200);
    return 0;
}

t_shared_instance <http_handler_http_handlers> _http_handlers;

return_t network_routine (uint32 type, uint32 data_count, void* data_array[], CALLBACK_CONTROL* callback_control, void* user_context)
{
    return_t ret = errorcode_t::success;
    net_session_socket_t* session_socket = (net_session_socket_t*) data_array[0];
    network_session* session = (network_session*) data_array[3];
    char* buf = (char*) data_array[1];
    size_t bufsize = (size_t) data_array[2];

    /* route */
    t_shared_instance <http_handler_http_handlers> router = _http_handlers;

    buffer_stream bs;
    std::string message;

    switch (type) {
        case mux_connect:
            std::cout << "connect " << session_socket->client_socket << std::endl;
            break;
        case mux_read:
            printf ("read %i (%zi) %.*s\n", session_socket->client_socket, bufsize, (unsigned) bufsize, buf);
            {
                http_request request;
                http_response response;
                ansi_string bs;
                request.open (buf, bufsize);
                std::cout << "url : " << request.get_url () << std::endl;
                std::cout << "method : " << request.get_method () << std::endl;

                /* URI, URL, query */
                http_uri* uri = request.get_uri ();
                for (size_t i = 0; i < uri->countof_query (); i++) {
                    std::string key;
                    std::string value;
                    uri->query (i, key, value);
                    std::cout << key.c_str () << " -> " << value.c_str () << std::endl;
                }

                /* header */
                std::string encoding;
                http_header* header = request.get_header ();
                header->get ("Accept-Encoding", encoding);
                std::cout << "encoding " << encoding.c_str () << std::endl;

                http_handler_t handler = router->find (request.get_url ());
                if (nullptr != handler) {
                    (*handler)(request.get_method (), request.get_url (), "", request.get_request (), &response);
                } else {
                    response.compose ("text/html", format ("<html><body>page not found %s</body></html>", request.get_url ()).c_str (), 200);
                }

                bool resp_wo_encoding = false;
                if (0 == stricmp (encoding.c_str (), "deflate")) {
                    buffer_stream encoded;
                    zlib_deflate (zlib_windowbits_t::windowbits_deflate, (byte_t*) response.content (), response.content_size (), &encoded);

                    bs.printf ("HTTP/1.1 200 OK\nConnection: Keep-Alive\nContent-Type: %s\nContent-Encoding: deflate\nContent-Length: %d\n\n%.*s",
                               response.content_type (), encoded.size (), encoded.size (), encoded.data ());
                } else if (0 == stricmp (encoding.c_str (), "gzip")) {
                    buffer_stream encoded;
                    zlib_deflate (zlib_windowbits_t::windowbits_zlib, (byte_t*) response.content (), response.content_size (), &encoded);

                    bs.printf ("HTTP/1.1 200 OK\nConnection: Keep-Alive\nContent-Type: %s\nContent-Encoding: gzip\nContent-Length: %d\n\n%.*s",
                               response.content_type (), encoded.size (), encoded.size (), encoded.data ());
                } else {
                    resp_wo_encoding = true;
                }

                if (resp_wo_encoding) {
                    bs.printf ("HTTP/1.1 200 OK\nConnection: Keep-Alive\nContent-Type: %s\nContent-Length: %d\n\n%s",
                               response.content_type (), response.content_size (), response.content ());
                }

                session->send ((const char*) bs.data (), bs.size ());
                fflush (stdout);
            }

            break;
        case mux_disconnect:
            std::cout << "disconnect " << session_socket->client_socket << std::endl;
            break;
    }
    return ret;
}

return_t echo_server (void*)
{
    return_t ret = errorcode_t::success;
    network_server netserver;
    void* handle_ipv4 = nullptr;
    void* handle_ipv6 = nullptr;

    FILE* fp = fopen (FILENAME_RUN, "w");

    fclose (fp);

    SSL_CTX* x509 = nullptr;
    http_protocol* http_prot = nullptr;
    transport_layer_security* tls = nullptr;
    transport_layer_security_server* tls_server = nullptr;

    __try2
    {
        // part of ssl certificate
        ret = x509_open (&x509, "server.crt", "server.key");
        _test_case.test (ret, __FUNCTION__, "x509");

        SSL_CTX_set_cipher_list (x509, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_8_SHA256:TLS_AES_128_CCM_SHA256");
        //SSL_CTX_set_cipher_list (x509, "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:AES128-GCM-SHA256:AES128-SHA256:AES256-GCM-SHA384:AES256-SHA256:!aNULL:!eNULL:!LOW:!EXP:!RC4");
        SSL_CTX_set_verify (x509, 0, nullptr);

        /* route */
        _http_handlers.make_share (new http_handler_http_handlers);
        _http_handlers->add ("/api/test1", api_test_handler);
        _http_handlers->add ("/api/v1/test", api_v1_test_handler);

        /* server */
        __try_new_catch (tls, new transport_layer_security (x509), ret, __leave2);
        __try_new_catch (http_prot, new http_protocol, ret, __leave2);
        __try_new_catch (tls_server, new transport_layer_security_server (tls), ret, __leave2);

        // start server
        netserver.open (&handle_ipv4, AF_INET, IPPROTO_TCP, PORT, 32000, network_routine, nullptr, tls_server);
        netserver.open (&handle_ipv6, AF_INET6, IPPROTO_TCP, PORT, 32000, network_routine, nullptr, tls_server);
        netserver.add_protocol (handle_ipv4, http_prot);

        netserver.consumer_loop_run (handle_ipv4, 2);
        netserver.consumer_loop_run (handle_ipv6, 2);
        netserver.event_loop_run (handle_ipv4, 2);
        netserver.event_loop_run (handle_ipv6, 2);

        while (true) {
            msleep (1000);

#if defined __linux__
            int chk = access (FILENAME_RUN, F_OK);
            if (errorcode_t::success != chk) {
                break;
            }
#elif defined _WIN32 || defined _WIN64
            uint32 dwAttrib = GetFileAttributes (FILENAME_RUN);
            if (INVALID_FILE_ATTRIBUTES == dwAttrib) {
                break;
            }
#endif
        }

        netserver.event_loop_break (handle_ipv4, 2);
        netserver.event_loop_break (handle_ipv6, 2);
        netserver.consumer_loop_break (handle_ipv4, 2);
        netserver.consumer_loop_break (handle_ipv6, 2);
    }
    __finally2
    {
        netserver.close (handle_ipv4);
        netserver.close (handle_ipv6);

        http_prot->release ();
        tls_server->release ();
        tls->release ();
        SSL_CTX_free (x509);
    }

    return ret;
}

void test_tlsserver ()
{
    thread thread1 (echo_server, nullptr);
    return_t ret = errorcode_t::success;

    __try2
    {
        _test_case.begin ("tls server");

        thread1.start ();
    }
    __finally2
    {
        thread1.wait (-1);
    }
}

int main ()
{
#if defined _WIN32 || defined _WIN64
    winsock_startup ();
#endif
    openssl_startup ();
    openssl_thread_setup ();

    test_tlsserver ();

    openssl_thread_end ();
    openssl_cleanup ();

#if defined _WIN32 || defined _WIN64
    winsock_cleanup ();
#endif

    _test_case.report ();
    return _test_case.result ();
}
