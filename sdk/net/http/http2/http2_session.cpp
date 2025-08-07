/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 *
 * TODO
 *      priority
 */

#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/system/types.hpp>
#include <sdk/net/http/http2/hpack.hpp>
#include <sdk/net/http/http2/http2_frame.hpp>
#include <sdk/net/http/http2/http2_frame_alt_svc.hpp>
#include <sdk/net/http/http2/http2_frame_continuation.hpp>
#include <sdk/net/http/http2/http2_frame_data.hpp>
#include <sdk/net/http/http2/http2_frame_goaway.hpp>
#include <sdk/net/http/http2/http2_frame_headers.hpp>
#include <sdk/net/http/http2/http2_frame_ping.hpp>
#include <sdk/net/http/http2/http2_frame_priority.hpp>
#include <sdk/net/http/http2/http2_frame_push_promise.hpp>
#include <sdk/net/http/http2/http2_frame_rst_stream.hpp>
#include <sdk/net/http/http2/http2_frame_settings.hpp>
#include <sdk/net/http/http2/http2_frame_window_update.hpp>
#include <sdk/net/http/http2/http2_serverpush.hpp>
#include <sdk/net/http/http2/http2_session.hpp>
#include <sdk/net/http/http_request.hpp>
#include <sdk/net/http/http_resource.hpp>
#include <sdk/net/http/http_server.hpp>
#include <sdk/net/server/network_session.hpp>

namespace hotplace {
namespace net {

http2_session::http2_session() : _enable_push(false) {}

http2_session& http2_session::consume(uint32 type, uint32 data_count, void* data_array[], http_server* server, http_request** request) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == data_array || nullptr == server || nullptr == request) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            netsocket_t* session_socket = (netsocket_t*)data_array[0];
            basic_stream dbs;

            switch (type) {
                case mux_connect:
                    dbs.println("[h2] connect %i", session_socket->event_handle->fd);
                    break;
                case mux_read: {
                    dbs.println("[h2] read %i", session_socket->event_handle->fd);
                    byte_t* buf = (byte_t*)data_array[1];
                    size_t bufsize = (size_t)data_array[2];
                    dump_memory((byte_t*)buf, bufsize, &dbs, 16, 2, 0, dump_memory_flag_t::dump_notrunc);
                } break;
                case mux_disconnect:
                    dbs.println("[h2] disconnect %i", session_socket->event_handle->fd);
                    break;
                default:
                    break;
            }
            trace_debug_event(trace_category_net, trace_event_net_consume, &dbs);
        }
#endif

        netsocket_t* session_socket = (netsocket_t*)data_array[0];
        byte_t* buf = (byte_t*)data_array[1];
        size_t bufsize = (size_t)data_array[2];

        network_session* session = (network_session*)data_array[3];

        binary_t bin_resp;
        consume(buf, bufsize, request, bin_resp);

        if (false == bin_resp.empty()) {
            session->send(&bin_resp[0], bin_resp.size());
        }
    }
    __finally2 {
        // do nothing
    }
    return *this;
}

return_t http2_session::consume(const byte_t* buf, size_t bufsize, http_request** request, binary_t& bin_resp) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == buf || nullptr == request) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        constexpr char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        const uint16 sizeof_preface = 24;
        bool stage_preface = false;
        uint32 pos_frame = 0;
        if (bufsize > sizeof_preface) {
            if (0 == strncmp((char*)buf, preface, sizeof_preface)) {
                stage_preface = true;
                pos_frame = sizeof_preface;
            }
        }

        http2_frame_header_t* hdr = (http2_frame_header_t*)(buf + pos_frame);
        size_t frame_size = bufsize - pos_frame;
        // uint24_t i32_24((byte_t*)hdr, frame_size);
        // uint32 payload_size = i32_24;
        // uint32 packet_size = sizeof(http2_frame_header_t) + payload_size;
        uint8 flags = hdr->flags;
        uint32 stream_id = ntoh32(hdr->stream_id);
        uint32 mask = (h2_flag_end_stream | h2_flag_end_headers);
        http_request* req = nullptr;
#if defined DEBUG
        basic_stream dbs;
#endif

        uint8 f = 0;
        flags_pib_t flags_pib = _flags.insert(std::make_pair(stream_id, flags));
        if (false == flags_pib.second) {
            flags_pib.first->second |= flags;
            flags = flags_pib.first->second;
        }
        headers_t ::iterator iter = _headers.find(stream_id);
        if (_headers.end() != iter) {
            req = &iter->second;
        } else {
            req = &_headers[stream_id];  // insert
            (*req).set_hpack_session(&get_hpack_session()).set_stream_id(stream_id).set_version(2);
        }

        bool completion = (mask == (mask & flags)) ? true : false;
        bool reset = false;

        if (h2_frame_t::h2_frame_data == hdr->type) {
            http2_frame_data frame;
            frame.read(hdr, frame_size);
#if defined DEBUG
            if (istraceable(trace_category_net)) {
                frame.dump(&dbs);
                trace_debug_event(trace_category_net, trace_event_net_consume, &dbs);
            }
#endif

            req->add_content(frame.get_data());

            if (req->get_http_header().contains("Content-Type", "application/x-www-form-urlencoded")) {
                auto const& content = req->get_content();
                req->get_http_uri().set_query(content);
            }
        } else if (h2_frame_t::h2_frame_headers == hdr->type) {
            http2_frame_headers frame;
            frame.read(hdr, frame_size);
            frame.set_hpack_session(&get_hpack_session());
#if defined DEBUG
            if (istraceable(trace_category_net)) {
                frame.dump(&dbs);
                trace_debug_event(trace_category_net, trace_event_net_consume, &dbs);
            }
#endif

            auto lambda = [&](const std::string& name, const std::string& value) -> void {
                if (":path" == name) {
                    req->get_http_uri().open(value);
                }
                req->get_http_header().add(name, value);
            };
            frame.read_compressed_header(frame.get_fragment(), lambda);
        } else if (h2_frame_t::h2_frame_priority == hdr->type) {
            http2_frame_priority frame;
            frame.read(hdr, frame_size);
#if defined DEBUG
            if (istraceable(trace_category_net)) {
                frame.dump(&dbs);
                trace_debug_event(trace_category_net, trace_event_net_consume, &dbs);
            }
#endif
        } else if (h2_frame_t::h2_frame_rst_stream == hdr->type) {
            http2_frame_rst_stream frame;
            frame.read(hdr, frame_size);
#if defined DEBUG
            if (istraceable(trace_category_net)) {
                frame.dump(&dbs);
                trace_debug_event(trace_category_net, trace_event_net_consume, &dbs);
            }
#endif
            reset = true;
        } else if (h2_frame_t::h2_frame_settings == hdr->type) {
            http2_frame_settings frame;
            frame.read(hdr, frame_size);
#if defined DEBUG
            if (istraceable(trace_category_net)) {
                frame.dump(&dbs);
                trace_debug_event(trace_category_net, trace_event_net_consume, &dbs);
            }
#endif

            // RFC 7541 6.5.2.  Defined SETTINGS Parameters
            // RFC 9113 6.5.2.  Defined Settings
            //                  SETTINGS_HEADER_TABLE_SIZE (0x01)
            //
            //  - http/2 frame type 4 SETTINGS
            //  > length 0x18(24) type 4 flags 00 stream identifier 00000000
            //  > flags [ ]
            //  > identifier 1 value 65536 (0x00010000)
            //  > identifier 2 value 0 (0x00000000)
            //  > identifier 4 value 6291456 (0x00600000)
            //  > identifier 6 value 262144 (0x00040000)

            uint32 table_size = 0;
            if (errorcode_t::success == frame.find(0x1, table_size)) {
                get_hpack_session().set_capacity(table_size);
            }
            uint32 push = 0;
            if (errorcode_t::success == frame.find(0x2, push)) {
                // RFC 7540 6.5.2.  Defined SETTINGS Parameters
                // SETTINGS_ENABLE_PUSH (0x2)
                enable_push(push ? true : false);
            }

            http2_frame_settings resp_settings;

            if (frame.get_flags()) {
                resp_settings.set_flags(h2_flag_ack);
            } else {
                resp_settings.add(h2_settings_enable_push, 0).add(h2_settings_max_concurrent_streams, 100).add(h2_settings_initial_window_size, 0xa00000);
            }

            resp_settings.write(bin_resp);
        } else if (h2_frame_t::h2_frame_push_promise == hdr->type) {
            http2_frame_push_promise frame;
            frame.read(hdr, frame_size);
            frame.set_hpack_session(&get_hpack_session());
#if defined DEBUG
            if (istraceable(trace_category_net)) {
                frame.dump(&dbs);
                trace_debug_event(trace_category_net, trace_event_net_consume, &dbs);
            }
#endif

            auto lambda = [&](const std::string& name, const std::string& value) -> void { req->get_http_header().add(name, value); };
            frame.read_compressed_header(frame.get_fragment(), lambda);
        } else if (h2_frame_t::h2_frame_ping == hdr->type) {
            http2_frame_ping frame;
            frame.read(hdr, frame_size);
#if defined DEBUG
            if (istraceable(trace_category_net)) {
                frame.dump(&dbs);
                trace_debug_event(trace_category_net, trace_event_net_consume, &dbs);
            }
#endif
            frame.set_flags(h2_flag_ack);
            frame.write(bin_resp);
        } else if (h2_frame_t::h2_frame_goaway == hdr->type) {
            http2_frame_goaway frame;
            frame.read(hdr, frame_size);
#if defined DEBUG
            if (istraceable(trace_category_net)) {
                frame.dump(&dbs);
                trace_debug_event(trace_category_net, trace_event_net_consume, &dbs);
            }
#endif
        } else if (h2_frame_t::h2_frame_window_update == hdr->type) {
            http2_frame_window_update frame;
            frame.read(hdr, frame_size);
#if defined DEBUG
            if (istraceable(trace_category_net)) {
                frame.dump(&dbs);
                trace_debug_event(trace_category_net, trace_event_net_consume, &dbs);
            }
#endif
        } else if (h2_frame_t::h2_frame_continuation == hdr->type) {
            http2_frame_continuation frame;
            frame.read(hdr, frame_size);
            frame.set_hpack_session(&get_hpack_session());
#if defined DEBUG
            if (istraceable(trace_category_net)) {
                frame.dump(&dbs);
                trace_debug_event(trace_category_net, trace_event_net_consume, &dbs);
            }
#endif

            auto lambda = [&](const std::string& name, const std::string& value) -> void { req->get_http_header().add(name, value); };
            frame.read_compressed_header(frame.get_fragment(), lambda);
        }

        /**
         * if END_HEADERS and END_STREAM is set
         * after handling DATA, HEADERS, CONTINUATION frames
         */
        if (completion) {
            *request = new http_request(*req);
        }
        if (completion || reset) {
            _flags.erase(stream_id);
            _headers.erase(stream_id);
        }
    }
    __finally2 {}
    return ret;
}

hpack_dynamic_table& http2_session::get_hpack_session() { return _hpack_dyntable; }

http2_session& http2_session::enable_push(bool enable) {
    _enable_push = enable;
    return *this;
}

bool http2_session::is_push_enabled() { return _enable_push; }

}  // namespace net
}  // namespace hotplace
