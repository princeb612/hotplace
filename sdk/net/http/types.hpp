/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_TYPES__
#define __HOTPLACE_SDK_NET_HTTP_TYPES__

#include <hotplace/sdk/net/server/types.hpp>
#include <hotplace/sdk/net/types.hpp>

namespace hotplace {
namespace net {

enum http_method_t {
    HTTP_OPTIONS = 1,
    HTTP_GET = 2,
    HTTP_HEAD = 3,
    HTTP_POST = 4,
    HTTP_PUT = 5,
    HTTP_DELETE = 6,
    HTTP_TRACE = 7,
};

// RFC 7541 HPACK: Header Compression for HTTP/2

enum match_result_t {
    not_matched = 0,
    /* HPACK, QPACK(static table) */
    key_matched = 1,
    all_matched = 2,
    /* QPACK(dynamic table) */
    key_matched_dynamic = 5,
    all_matched_dynamic = 6,
};

enum http_header_compression_flag_t : uint32 {
    // encoding/decoding
    hpack_huffman = (1 << 0),        // 0x00000001
    hpack_indexing = (1 << 1),       // 0x00000002
    hpack_wo_indexing = (1 << 2),    // 0x00000004
    hpack_never_indexed = (1 << 3),  // 0x00000008

    // encoding/decoding
    qpack_huffman = hpack_huffman,    // 0x00000001
    qpack_indexing = hpack_indexing,  // 0x00000002
    qpack_static = (1 << 7),          // 0x00000080
    qpack_intermediary = (1 << 8),    // 0x00000100
    qpack_postbase_index = (1 << 9),  // 0x00000200
    qpack_name_reference = (1 << 5),  // 0x00000020

    // analysis layout while decoding
    hpack_layout_index = (1 << 4),         // 0x00000010
    hpack_layout_indexed_name = (1 << 5),  // 0x00000020
    hpack_layout_name_value = (1 << 6),    // 0x00000040
    hpack_layout_capacity = (1 << 10),     // 0x00000400

    // analysis layout while decoding
    qpack_layout_capacity = (1 << 10),       // 0x00000400
    qpack_layout_index = (1 << 4),           // 0x00000010
    qpack_layout_name_reference = (1 << 5),  // 0x00000020
    qpack_layout_name_value = (1 << 6),      // 0x00000040
    qpack_layout_duplicate = (1 << 11),      // 0x00000800
    qpack_layout_ack = (1 << 12),            // 0x00001000
    qpack_layout_cancel = (1 << 13),         // 0x00002000
    qpack_layout_inc = (1 << 14),            // 0x00004000
    qpack_field_section_prefix = (1 << 18),  // 0x00040000

    qpack_quic_stream_encoder = (1 << 15),  // 0x00008000
    qpack_quic_stream_decoder = (1 << 16),  // 0x00010000
    qpack_quic_stream_header = (1 << 17),   // 0x00020000
};

// net/http
class html_documents;
class http_authentication_provider;
class http_authentication_resolver;
class http_client;
class http_header;
class http_protocol;
class http_request;
class http_resource;
class http_response;
class http_router;
class http_server;
class http_server_builder;
class http_uri;

// net/http/compression
class http_header_compression;
class http_huffman_coding;

// net/http/http2
class hpack_encoder;
class hpack_dynamic_table;
class hpack_static_table;
class http_static_table;
class http_dynamic_table;
class http2_frame;
class http2_frame_builder;
class http2_frame_alt_svc;
class http2_frame_continuation;
class http2_frame_data;
class http2_frame_goaway;
class http2_frame_headers;
class http2_frame_ping;
class http2_frame_priority;
class http2_frame_push_promise;
class http2_frame_rst_stream;
class http2_frame_settings;
class http2_frame_window_update;
class http2_frames;
class http2_protocol;
class http2_serverpush;
class http2_session;

// net/http/http3
class qpack_encoder;
class qpack_dynamic_table;
class qpack_static_table;
class http3_frame;
class http3_frame_builder;
class http3_frame_data;
class http3_frame_headers;
class http3_frame_cancel_push;
class http3_frame_settings;
class http3_frame_push_promise;
class http3_frame_goaway;
class http3_frame_origin;
class http3_frame_max_push_id;
class http3_frame_metadata;
class http3_frame_priority_pdate;
class http3_frame_unknown;
class http3_frames;

// hpack_strea, qpack_stream
template <typename DYNAMIC_T, typename ENCODER_T>
class http_header_compression_stream;

}  // namespace net
}  // namespace hotplace

#endif
