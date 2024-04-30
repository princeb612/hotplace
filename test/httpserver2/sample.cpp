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
    // valgrind
    critical_section_guard guard(print_lock);
    va_list ap;
    va_start(ap, text);
    vprintf(text, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
}

void dump_frame(http2_frame_header* base, http2_frame_header_t* hdr, size_t size, hpack_encoder* encoder = nullptr, hpack_session* session = nullptr) {
    basic_stream bs;
    base->read(hdr, size);
    base->dump(&bs);
    printf("%s", bs.c_str());
    fflush(stdout);
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

            if (errorcode_t::success == _http_server->get_http2_protocol().is_kind_of(buf, bufsize)) {
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

                http2_frame_header_t* hdr = (http2_frame_header_t*)(buf + pos_frame);
                size_t checksize = bufsize - pos_frame;
                uint32_24_t i32_24((byte_t*)hdr, checksize);
                uint32 payload_size = i32_24.get();
                uint32 packet_size = sizeof(http2_frame_header_t) + payload_size;

                if (h2_frame_t::h2_frame_data == hdr->type) {
                    http2_frame_data frame;
                    dump_frame(&frame, hdr, checksize);
                } else if (h2_frame_t::h2_frame_headers == hdr->type) {
                    http2_frame_headers frame;
                    frame.set_hpack_encoder(&_http_server->get_hpack_encoder()).set_hpack_session(session->get_hpack_session());
                    dump_frame(&frame, hdr, checksize);

                    uint32 stream_id = frame.get_stream_id();

                    hpack hp;
                    binary_t bin_resp;
                    const char* resp = "<html><body>hello</body></html>";

                    // header compression
                    {
                        hp.set_encoder(&_http_server->get_hpack_encoder())
                            .set_session(session->get_hpack_session())
                            .set_encode_flags(hpack_indexing | hpack_huffman)
                            .encode_header(":status", "200")
                            .encode_header("content-type", "text/html")
                            .encode_header("content-length", format("%zi", strlen(resp)).c_str());
                        if (option.verbose) {
                            dump_memory(hp.get_binary(), &bs, 16, 2);
                            printf("dump HPACK\n%s\n", bs.c_str());
                        }
                    }

                    // response headers
                    {
                        // - END_STREAM
                        // + END_HEADERS
                        http2_frame_headers resp_headers;
                        resp_headers.set_hpack_encoder(&_http_server->get_hpack_encoder())
                            .set_hpack_session(session->get_hpack_session())
                            .set_flags(h2_flag_end_headers)
                            .set_stream_id(stream_id);
                        resp_headers.get_fragment() = hp.get_binary();
                        resp_headers.write(bin_resp);
                    }

                    // response data
                    {
                        // + END_STREAM
                        http2_frame_data resp_data;
                        resp_data.set_flags(h2_flag_end_stream).set_stream_id(stream_id);

                        resp_data.get_data() = convert(resp);
                        resp_data.write(bin_resp);
                    }

                    // response
                    {
                        // + END_STREAM
                        // + END_HEADERS
                        http2_frame_headers resp_headers2;
                        resp_headers2.set_flags(h2_flag_end_stream | h2_flag_end_headers).set_stream_id(stream_id);
                        resp_headers2.write(bin_resp);
                    }

                    // dump response
                    if (option.verbose) {
                        dump_memory(bin_resp, &bs, 16, 2);
                        printf("dump (headers+data)\n%s\n", bs.c_str());
                    }

                    session->send((char*)&bin_resp[0], bin_resp.size());

                } else if (h2_frame_t::h2_frame_priority == hdr->type) {
                    http2_frame_priority frame;
                    dump_frame(&frame, hdr, checksize);
                } else if (h2_frame_t::h2_frame_rst_stream == hdr->type) {
                    http2_frame_rst_stream frame;
                    dump_frame(&frame, hdr, checksize);
                } else if (h2_frame_t::h2_frame_settings == hdr->type) {
                    http2_frame_settings frame;
                    dump_frame(&frame, hdr, checksize);

                    binary_t bin_resp;
                    http2_frame_settings resp_settings;

                    if (frame.get_flags()) {
                        resp_settings.set_flags(h2_flag_ack);
                    } else {
                        resp_settings.add(h2_settings_enable_push, 0).add(h2_settings_max_concurrent_streams, 100);
                    }

                    resp_settings.write(bin_resp);

                    dump_memory(bin_resp, &bs, 16, 2);
                    printf("dump (sessings)\n%s\n", bs.c_str());

                    session->send((char*)&bin_resp[0], bin_resp.size());

                } else if (h2_frame_t::h2_frame_push_promise == hdr->type) {
                    http2_frame_push_promise frame;
                    frame.set_hpack_encoder(&_http_server->get_hpack_encoder()).set_hpack_session(session->get_hpack_session());
                    dump_frame(&frame, hdr, checksize);
                } else if (h2_frame_t::h2_frame_ping == hdr->type) {
                    http2_frame_ping frame;
                    dump_frame(&frame, hdr, checksize);
                } else if (h2_frame_t::h2_frame_goaway == hdr->type) {
                    http2_frame_goaway frame;
                    dump_frame(&frame, hdr, checksize);
                } else if (h2_frame_t::h2_frame_window_update == hdr->type) {
                    http2_frame_window_update frame;
                    dump_frame(&frame, hdr, checksize);
                } else if (h2_frame_t::h2_frame_continuation == hdr->type) {
                    http2_frame_continuation frame;
                    frame.set_hpack_encoder(&_http_server->get_hpack_encoder()).set_hpack_session(session->get_hpack_session());
                    dump_frame(&frame, hdr, checksize);
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
            .enable_h2(true)  // enable HTTP/2
            .set_handler(consume_routine);
        builder.get_server_conf()
            .set(netserver_config_t::serverconf_concurrent_tls_accept, 2)
            .set(netserver_config_t::serverconf_concurrent_network, 4)
            .set(netserver_config_t::serverconf_concurrent_consume, 4);
        _http_server.make_share(builder.build());

        _http_server->get_http_protocol().set_constraints(protocol_constraints_t::protocol_packet_size, 1 << 14);
        _http_server->get_http2_protocol().set_constraints(protocol_constraints_t::protocol_packet_size, 1 << 14);

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
