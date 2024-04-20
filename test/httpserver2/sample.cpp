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
 * @comments
 *      debug w/ curl
 *      curl -v -k https://localhost:9000 --http2  --http2-prior-knowledge
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
t_shared_instance<http_protocol> h1_protocol;
t_shared_instance<http2_protocol> h2_protocol;
critical_section print_lock;

void cprint(const char* text, ...) {
    critical_section_guard guard(print_lock);
    console_color _concolor;

    std::cout << _concolor.turnon().set_fgcolor(console_color_t::cyan);
    va_list ap;
    va_start(ap, text);
    vprintf(text, ap);
    va_end(ap);
    std::cout << _concolor.turnoff() << std::endl;
}

void print(const char* text, ...) {
    critical_section_guard guard(print_lock);
    va_list ap;
    va_start(ap, text);
    vprintf(text, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
}

template <typename H2_FRAME_TYPE>
void dump_frame(http2_frame_header_t* frame, size_t size) {
    H2_FRAME_TYPE fr;
    fr.read(frame, size);

    basic_stream bs;
    fr.dump(&bs);
    print("%s", bs.c_str());
}

return_t consume_routine(uint32 type, uint32 data_count, void* data_array[], CALLBACK_CONTROL* callback_control, void* user_context) {
    return_t ret = errorcode_t::success;
    net_session_socket_t* session_socket = (net_session_socket_t*)data_array[0];
    network_session* session = (network_session*)data_array[3];
    char* buf = (char*)data_array[1];
    size_t bufsize = (size_t)data_array[2];

    binary_t bin;
    basic_stream bs;
    std::string message;

    OPTION& option = cmdline->value();
    t_shared_instance<http2_protocol> http2_prot = h2_protocol;

    switch (type) {
        case mux_connect:
            cprint("connect %i", session_socket->cli_socket);
            break;
        case mux_read:
            cprint("read %i", session_socket->cli_socket);
            if (option.debug) {
                dump_memory((byte_t*)buf, bufsize, &bs, 16, 2);
                print("consume\n%s", bs.c_str());
                bs.clear();
            }

            // studying .... debug frames ...

            if (errorcode_t::success == h2_protocol->is_kind_of(buf, bufsize)) {
                constexpr char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
                const uint16 sizeof_preface = 24;
                bool stage_preface = false;
                uint32 pos_frame = 0;
                if (bufsize > sizeof_preface) {
                    if (0 == strncmp(buf, preface, sizeof_preface)) {
                        print("- http/2 connecton preface");
                        stage_preface = true;
                        pos_frame = sizeof_preface;
                    }
                }

                http2_frame_header_t* frame = (http2_frame_header_t*)(buf + pos_frame);
                size_t checksize = bufsize - pos_frame;
                uint32_24_t i32_24((byte_t*)frame, checksize);
                uint32 payload_size = i32_24.get();
                uint32 packet_size = sizeof(http2_frame_header_t) + payload_size;

                if (h2_frame_t::h2_frame_data == frame->type) {
                    dump_frame<http2_data_frame>(frame, checksize);
                } else if (h2_frame_t::h2_frame_headers == frame->type) {
                    dump_frame<http2_headers_frame>(frame, checksize);
                } else if (h2_frame_t::h2_frame_priority == frame->type) {
                    dump_frame<http2_priority_frame>(frame, checksize);
                } else if (h2_frame_t::h2_frame_rst_stream == frame->type) {
                    dump_frame<http2_rst_stream_frame>(frame, checksize);
                } else if (h2_frame_t::h2_frame_settings == frame->type) {
                    dump_frame<http2_settings_frame>(frame, checksize);

                    // {
                    //     if (stage_preface) {
                    //         settings.add(h2_settings_param_t::h2_settings_header_table_size, 1 << 12);
                    //         settings.add(h2_settings_param_t::h2_settings_max_concurrent_streams, 100);
                    //         settings.add(h2_settings_param_t::h2_settings_initial_window_size, 1 << 16);
                    //         settings.add(h2_settings_param_t::h2_settings_max_frame_size, 1 << 14);
                    //         settings.add(h2_settings_param_t::h2_settings_max_header_list_size, 1 << 14);
                    //     }
                    //     if (frame->flags & h2_flag_t::h2_flag_ack) {
                    //         settings.set_flags(h2_flag_t::h2_flag_ack);
                    //     }
                    //
                    //     settings.write(bin);
                    //     if (option.debug) {
                    //         dump_memory(bin, &bs);
                    //         print("dump\n%s\n", bs.c_str());
                    //     }
                    //
                    //     // session->send((char*)&bin[0], bin.size());
                    // }
                } else if (h2_frame_t::h2_frame_push_promise == frame->type) {
                    dump_frame<http2_push_promise_frame>(frame, checksize);
                } else if (h2_frame_t::h2_frame_ping == frame->type) {
                    dump_frame<http2_ping_frame>(frame, checksize);
                } else if (h2_frame_t::h2_frame_goaway == frame->type) {
                    dump_frame<http2_goaway_frame>(frame, checksize);
                } else if (h2_frame_t::h2_frame_window_update == frame->type) {
                    dump_frame<http2_window_update_frame>(frame, checksize);
                } else if (h2_frame_t::h2_frame_continuation == frame->type) {
                    dump_frame<http2_continuation_frame>(frame, checksize);
                }
            } else {
                http_response resp;
                resp.compose(200, "text/html", "<html><body><pre>hello</pre></body></html>");
                resp.respond(session);
            }
            break;
        case mux_disconnect:
            cprint("disconnect %i", session_socket->cli_socket);
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

    http_protocol* http1_prot = nullptr;
    http2_protocol* http2_prot = nullptr;
    tcp_server_socket svr_sock;
    transport_layer_security* tls = nullptr;
    tls_server_socket* tls_server = nullptr;

    // part of ssl certificate
    x509cert cert("server.crt", "server.key");
    cert.set_cipher_list("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_8_SHA256:TLS_AES_128_CCM_SHA256")
        .set_verify(0);

    __try2 {
        /* server */
        __try_new_catch(tls, new transport_layer_security(cert.get()), ret, __leave2);
        __try_new_catch(http1_prot, new http_protocol, ret, __leave2);
        __try_new_catch(http2_prot, new http2_protocol, ret, __leave2);
        __try_new_catch(tls_server, new tls_server_socket(tls), ret, __leave2);

        http2_prot->set_constraints(protocol_constraints_t::protocol_packet_size, 1 << 14);

        h1_protocol.make_share(http1_prot);
        h2_protocol.make_share(http2_prot);

        // start server
        netserver.open(&handle_http_ipv4, AF_INET, IPPROTO_TCP, option.port, 1024, consume_routine, nullptr, &svr_sock);
        netserver.open(&handle_http_ipv6, AF_INET6, IPPROTO_TCP, option.port, 1024, consume_routine, nullptr, &svr_sock);
        netserver.open(&handle_https_ipv4, AF_INET, IPPROTO_TCP, option.port_tls, 1024, consume_routine, nullptr, tls_server);
        netserver.open(&handle_https_ipv6, AF_INET6, IPPROTO_TCP, option.port_tls, 1024, consume_routine, nullptr, tls_server);
        netserver.add_protocol(handle_http_ipv4, http1_prot);
        netserver.add_protocol(handle_http_ipv6, http1_prot);
        netserver.add_protocol(handle_https_ipv4, http1_prot);
        netserver.add_protocol(handle_https_ipv6, http1_prot);
        netserver.add_protocol(handle_http_ipv4, http2_prot);
        netserver.add_protocol(handle_http_ipv6, http2_prot);
        netserver.add_protocol(handle_https_ipv4, http2_prot);
        netserver.add_protocol(handle_https_ipv6, http2_prot);

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
