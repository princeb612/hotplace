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

#if 0
connect 640
read 640
consume
  00000000 : 50 52 49 20 2A 20 48 54 54 50 2F 32 2E 30 0D 0A | PRI * HTTP/2.0..
  00000010 : 0D 0A 53 4D 0D 0A 0D 0A 00 00 12 04 00 00 00 00 | ..SM............
  00000020 : 00 00 03 00 00 00 64 00 04 00 A0 00 00 00 02 00 | ......d.........
  00000030 : 00 00 00 -- -- -- -- -- -- -- -- -- -- -- -- -- | ...
- http/2 connecton preface
- http/2 frame type 4 SETTINGS
> length 18 type 4 flags 00 stream identifier 0
> flags [ ]
> identifier 2 value 0 (0x00000000)
> identifier 3 value 100 (0x00000064)
> identifier 4 value 10485760 (0x00a00000)

read 640
consume
  00000000 : 00 00 04 08 00 00 00 00 00 3E 7F 00 01 -- -- -- | .........>...
- http/2 frame type 8 WINDOW_UPDATE
> length 4 type 8 flags 00 stream identifier 0
> flags [ ]
> window size increment 1048510465

read 640
consume
  00000000 : 00 00 1E 01 05 00 00 00 01 82 87 41 8A A0 E4 1D | ...........A....
  00000010 : 13 9D 09 B8 F8 00 0F 84 7A 88 25 B6 50 C3 CB 89 | ........z.%.P...
  00000020 : 70 FF 53 03 2A 2F 2A -- -- -- -- -- -- -- -- -- | p.S.*/*
- http/2 frame type 1 HEADERS
> length 30 type 1 flags 05 stream identifier 1
> flags [ END_STREAM END_HEADERS ]
> fragment
  00000000 : 82 87 41 8A A0 E4 1D 13 9D 09 B8 F8 00 0F 84 7A | ..A............z
  00000010 : 88 25 B6 50 C3 CB 89 70 FF 53 03 2A 2F 2A -- -- | .%.P...p.S.*/*

disconnect 640
#endif

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
    int verbose;

    _OPTION() : port(8080), port_tls(9000), verbose(0) {}
} OPTION;

t_shared_instance<cmdline_t<OPTION> > cmdline;
t_shared_instance<http_server> _http_server;
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

    switch (type) {
        case mux_connect:
            cprint("connect %i", session_socket->cli_socket);
            break;
        case mux_read:
            cprint("read %i", session_socket->cli_socket);
            if (option.verbose) {
                dump_memory((byte_t*)buf, bufsize, &bs, 16, 2);
                print("consume\n%s", bs.c_str());
                bs.clear();
            }

            // studying .... debug frames ...

            if (errorcode_t::success == _http_server->get_http2_protocol()->is_kind_of(buf, bufsize)) {
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
            .enable_h2(true)
            .set_handler(consume_routine);
        builder.get_server_conf()
            .set(netserver_config_t::serverconf_concurrent_tls_accept, 2)
            .set(netserver_config_t::serverconf_concurrent_network, 4)
            .set(netserver_config_t::serverconf_concurrent_consume, 4);
        _http_server.make_share(builder.build());

        _http_server->get_http_protocol()->set_constraints(protocol_constraints_t::protocol_packet_size, 1 << 14);
        _http_server->get_http2_protocol()->set_constraints(protocol_constraints_t::protocol_packet_size, 1 << 14);

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
    *cmdline << cmdarg_t<OPTION>("-h", "http  port (default 8080)", [&](OPTION& o, char* param) -> void { o.port = atoi(param); }).preced().optional()
             << cmdarg_t<OPTION>("-s", "https port (default 9000)", [&](OPTION& o, char* param) -> void { o.port_tls = atoi(param); }).preced().optional()
             << cmdarg_t<OPTION>("-v", "verbose", [&](OPTION& o, char* param) -> void { o.verbose = 1; }).optional();

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
