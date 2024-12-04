/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/quic/quic.hpp>
#include <sdk/net/tlsspec/tlsspec.hpp>

namespace hotplace {
namespace net {

// understanding ...

return_t quic_dump_frame(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_role_t role) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == stream || 0 == size) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (pos > size) {
            ret = errorcode_t::no_data;
            __leave2;
        }

        auto begin = pos;

        // RFC 9001 19.  Frame Types and Formats
        uint64 value = 0;
        ret = quic_read_vle_int(stream, size, pos, value);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        uint8 frame_type = value;

        constexpr char constexpr_frame_padding[] = "PADDING";
        constexpr char constexpr_frame_ping[] = "PING";
        constexpr char constexpr_frame_ack[] = "ACK";
        constexpr char constexpr_frame_reset_stream[] = "RESET_STREAM";
        constexpr char constexpr_frame_stop_sending[] = "STOP_SENDING";
        constexpr char constexpr_frame_crypto[] = "CRYPTO";
        constexpr char constexpr_frame_new_token[] = "NEW_TOKEN";
        constexpr char constexpr_frame_stream[] = "STREAM";
        constexpr char constexpr_frame_max_data[] = "MAX_DATA";
        constexpr char constexpr_frame_max_stream_data[] = "MAX_STREAM_DATA";
        constexpr char constexpr_frame_max_streams[] = "MAX_STREAMS";
        constexpr char constexpr_frame_data_blocked[] = "DATA_BLOCKED";
        constexpr char constexpr_frame_stream_data_blocked[] = "STREAM_DATA_BLOCKED";
        constexpr char constexpr_frame_streams_blocked[] = "STREAMS_BLOCKED";
        constexpr char constexpr_frame_new_connection_id[] = "NEW_CONNECTION_ID";
        constexpr char constexpr_frame_retire_connection_id[] = "RETIRE_CONNECTION_ID";
        constexpr char constexpr_frame_path_challenge[] = "PATH_CHALLENGE";
        constexpr char constexpr_frame_path_response[] = "PATH_RESPONSE";
        constexpr char constexpr_frame_connection_close[] = "CONNECTION_CLOSE";
        constexpr char constexpr_frame_handshake_done[] = "HANDSHAKE_DONE";

        constexpr char constexpr_stream_id[] = "stream id";
        constexpr char constexpr_error_code[] = "error code";

        switch (frame_type) {
            // RFC 9001 19.1.  PADDING Frames
            case quic_frame_padding:
                // PADDING Frame {
                //   Type (i) = 0x00,
                // }
                // Figure 23: PADDING Frame Format
                s->printf("  > frame %s @%zi\n", constexpr_frame_padding, begin);
                break;
            // RFC 9001 19.2.  PING Frames
            case quic_frame_ping:
                // PING Frame {
                //     Type (i) = 0x01,
                // }
                // Figure 24: PING Frame Format
                s->printf("  > frame %s @%zi\n", constexpr_frame_ping, begin);
                break;
            // RFC 9001 19.3.  ACK Frames
            case quic_frame_ack:
            case quic_frame_ack + 1: {
                // ACK Frame {
                //   Type (i) = 0x02..0x03,
                //   Largest Acknowledged (i),
                //   ACK Delay (i),
                //   ACK Range Count (i),
                //   First ACK Range (i),
                //   ACK Range (..) ...,
                //   [ECN Counts (..)],
                // }
                // Figure 25: ACK Frame Format

                constexpr char constexpr_largest_ack[] = "largest ack";
                constexpr char constexpr_ack_delay[] = "ack delay";
                constexpr char constexpr_ack_range_count[] = "ack range count";
                constexpr char constexpr_first_ack_range[] = "first ack range";

                constexpr char constexpr_ecn_counts[] = "ECN Counts";
                constexpr char constexpr_ect0_count[] = "ect0 count";
                constexpr char constexpr_ect1_count[] = "ect1 count";
                constexpr char constexpr_ectce_count[] = "ect-ce count";

                payload pl;
                pl << new payload_member(new quic_encoded(uint64(0)), constexpr_largest_ack)
                   << new payload_member(new quic_encoded(uint64(0)), constexpr_ack_delay)
                   << new payload_member(new quic_encoded(uint64(0)), constexpr_ack_range_count)
                   << new payload_member(new quic_encoded(uint64(0)), constexpr_first_ack_range);
                pl.read(stream, size, pos);

                uint64 largest_ack = pl.select(constexpr_largest_ack)->get_payload_encoded()->value();
                uint64 ack_delay = pl.select(constexpr_ack_delay)->get_payload_encoded()->value();
                uint64 ack_range_count = pl.select(constexpr_ack_range_count)->get_payload_encoded()->value();
                uint64 first_ack_range = pl.select(constexpr_first_ack_range)->get_payload_encoded()->value();

                s->printf("  > frame %s @%zi\n", constexpr_frame_ack, begin);
                s->printf("   > %s %I64i\n", constexpr_largest_ack, largest_ack);
                s->printf("   > %s %I64i\n", constexpr_ack_delay, ack_delay);
                s->printf("   > %s %I64i\n", constexpr_ack_range_count, ack_range_count);
                s->printf("   > %s %I64i\n", constexpr_first_ack_range, first_ack_range);

                constexpr char constexpr_ack_ranges[] = "ack ranges";
                constexpr char constexpr_gap[] = "gap";
                constexpr char constexpr_range_length[] = "range length";

                // RFC 9001 19.3.1.  ACK Ranges
                for (uint64 i = 0; i < ack_range_count; i++) {
                    // ACK Range {
                    //   Gap (i),
                    //   ACK Range Length (i),
                    // }
                    // Figure 26: ACK Ranges
                    payload ack_ranges;
                    ack_ranges << new payload_member(new quic_encoded(uint64(0)), constexpr_gap)
                               << new payload_member(new quic_encoded(uint64(0)), constexpr_range_length);
                    ack_ranges.read(stream, size, pos);

                    uint64 gap = ack_ranges.select(constexpr_gap)->get_payload_encoded()->value();
                    uint64 range_length = ack_ranges.select(constexpr_range_length)->get_payload_encoded()->value();

                    s->printf("   > %s\n", constexpr_ack_ranges);
                    s->printf("    > %s %I64i\n", constexpr_gap, gap);
                    s->printf("    > %s %I64i\n", constexpr_range_length, range_length);
                }

                // RFC 9001 19.3.2.  ECN Counts
                if (3 == frame_type) {
                    // ECN Counts {
                    //   ECT0 Count (i),
                    //   ECT1 Count (i),
                    //   ECN-CE Count (i),
                    // }
                    // Figure 27: ECN Count Format
                    payload ecn_counts;
                    ecn_counts << new payload_member(new quic_encoded(uint64(0)), constexpr_ect0_count)
                               << new payload_member(new quic_encoded(uint64(0)), constexpr_ect1_count)
                               << new payload_member(new quic_encoded(uint64(0)), constexpr_ectce_count);
                    ecn_counts.read(stream, size, pos);

                    uint64 ect0_count = ecn_counts.select(constexpr_ect0_count)->get_payload_encoded()->value();
                    uint64 ect1_count = ecn_counts.select(constexpr_ect1_count)->get_payload_encoded()->value();
                    uint64 ectce_count = ecn_counts.select(constexpr_ectce_count)->get_payload_encoded()->value();

                    s->printf("   > %s\n", constexpr_ecn_counts);
                    s->printf("    > %s %I64i\n", constexpr_ect0_count, ect0_count);
                    s->printf("    > %s %I64i\n", constexpr_ect1_count, ect1_count);
                    s->printf("    > %s %I64i\n", constexpr_ectce_count, ectce_count);
                }
            } break;
            // 19.4.  RESET_STREAM Frames
            case quic_frame_reset_stream: {
                // RESET_STREAM Frame {
                //   Type (i) = 0x04,
                //   Stream ID (i),
                //   Application Protocol Error Code (i),
                //   Final Size (i),
                // }
                // Figure 28: RESET_STREAM Frame Format
                constexpr char constexpr_final_size[] = "final size";

                payload pl;
                pl << new payload_member(new quic_encoded(uint64(0)), constexpr_stream_id)
                   << new payload_member(new quic_encoded(uint64(0)), constexpr_error_code)
                   << new payload_member(new quic_encoded(uint64(0)), constexpr_final_size);
                pl.read(stream, size, pos);

                uint64 stream_id = pl.select(constexpr_stream_id)->get_payload_encoded()->value();
                uint64 error_code = pl.select(constexpr_error_code)->get_payload_encoded()->value();
                uint64 final_size = pl.select(constexpr_final_size)->get_payload_encoded()->value();

                s->printf("  > frame %s @%zi\n", constexpr_frame_reset_stream, begin);
                s->printf("   > %s %I64i\n", constexpr_stream_id, stream_id);
                s->printf("   > %s %I64i\n", constexpr_error_code, error_code);
                s->printf("   > %s %I64i\n", constexpr_final_size, final_size);
            } break;
            // 19.5.  STOP_SENDING Frames
            case quic_frame_stop_sending: {
                // STOP_SENDING Frame {
                //     Type (i) = 0x05,
                //     Stream ID (i),
                //     Application Protocol Error Code (i),
                // }
                // Figure 29: STOP_SENDING Frame Format
                payload pl;
                pl << new payload_member(new quic_encoded(uint64(0)), constexpr_stream_id)
                   << new payload_member(new quic_encoded(uint64(0)), constexpr_error_code);
                pl.read(stream, size, pos);

                uint64 stream_id = pl.select(constexpr_stream_id)->get_payload_encoded()->value();
                uint64 error_code = pl.select(constexpr_error_code)->get_payload_encoded()->value();

                s->printf("  > frame %s @%zi\n", constexpr_frame_stop_sending, begin);
                s->printf("   > %s %I64i\n", constexpr_stream_id, stream_id);
                s->printf("   > %s %I64i\n", constexpr_error_code, error_code);
            } break;
            // 19.6.  CRYPTO Frames
            case quic_frame_crypto: {
                // CRYPTO Frame {
                //   Type (i) = 0x06,
                //   Offset (i),
                //   Length (i),
                //   Crypto Data (..),
                // }
                // Figure 30: CRYPTO Frame Format
                constexpr char constexpr_length[] = "length";
                constexpr char constexpr_offset[] = "offset";
                constexpr char constexpr_crypto_data[] = "crypto data";

                payload pl;
                pl << new payload_member(new quic_encoded(uint64(0)), constexpr_offset) << new payload_member(new quic_encoded(uint64(0)), constexpr_length)
                   << new payload_member(binary_t(), constexpr_crypto_data);
                pl.set_reference_value(constexpr_crypto_data, constexpr_length);
                pl.read(stream, size, pos);

                uint64 offset = pl.select(constexpr_offset)->get_payload_encoded()->value();
                uint64 length = pl.select(constexpr_length)->get_payload_encoded()->value();
                binary_t crypto_data;
                pl.select(constexpr_crypto_data)->get_variant().to_binary(crypto_data);

                s->printf("  > frame %s @%zi\n", constexpr_frame_crypto, begin);
                s->printf("   > %s %I64i\n", constexpr_offset, offset);
                s->printf("   > %s %I64i\n", constexpr_length, length);
                s->printf("   > %s (%zi)\n", constexpr_crypto_data, crypto_data.size());
                dump_memory(crypto_data, s, 16, 5, 0x0, dump_notrunc);
                s->printf("\n");

                size_t hpos = 0;
                tls_dump_handshake(s, session, &crypto_data[0], crypto_data.size(), hpos, role);
            } break;
            // 19.7.  NEW_TOKEN Frames
            case quic_frame_new_token: {
                // NEW_TOKEN Frame {
                //   Type (i) = 0x07,
                //   Token Length (i),
                //   Token (..),
                // }
                // Figure 31: NEW_TOKEN Frame Format
                constexpr char constexpr_token[] = "token";

                payload pl;
                pl << new payload_member(new quic_encoded(binary_t()), constexpr_token);
                pl.read(stream, size, pos);

                binary_t token;
                pl.select(constexpr_token)->get_variant().to_binary(token);

                s->printf("  > frame %s @%zi\n", constexpr_frame_new_token, begin);
                s->printf("   > %s (%zi)\n", constexpr_token, token.size());
                dump_memory(token, s, 16, 5, 0x0, dump_notrunc);
                s->printf("\n");
            } break;
            // 19.8.  STREAM Frames
            case quic_frame_stream:      // 0x8
            case quic_frame_stream + 1:  // 0x9
            case quic_frame_stream + 2:  // 0xa
            case quic_frame_stream + 3:  // 0xb
            case quic_frame_stream + 4:  // 0xc
            case quic_frame_stream + 5:  // 0xd
            case quic_frame_stream + 6:  // 0xe
            case quic_frame_stream + 7:  // 0xf
            {
                // STREAM Frame {
                //   Type (i) = 0x08..0x0f,
                //   Stream ID (i),
                //   [Offset (i)],
                //   [Length (i)],
                //   Stream Data (..),
                // }
                // Figure 32: STREAM Frame Format
            } break;
            case quic_frame_max_data:
                // Figure 33: MAX_DATA Frame Format
                break;
            case quic_frame_max_stream_data:
                // Figure 34: MAX_STREAM_DATA Frame Format
                break;
            case quic_frame_max_streams:
                // Figure 35: MAX_STREAMS Frame Format
                break;
            case quic_frame_data_blocked:
                // Figure 36: DATA_BLOCKED Frame Format
                break;
            case quic_frame_stream_data_blocked:
                // Figure 37: STREAM_DATA_BLOCKED Frame Format
                break;
            case quic_frame_stream_blocked:
                // Figure 38: STREAMS_BLOCKED Frame Format
                break;
            case quic_frame_new_connection_id:
                // Figure 39: NEW_CONNECTION_ID Frame Format
                break;
            case quic_frame_retire_connection_id:
                // Figure 40: RETIRE_CONNECTION_ID Frame Format
                break;
            case quic_frame_path_challenge:
                // Figure 41: PATH_CHALLENGE Frame Format
                break;
            case quic_frame_path_response:
                // Figure 42: PATH_RESPONSE Frame Format
                break;
            case quic_frame_connection_close:
                // Figure 43: CONNECTION_CLOSE Frame Format
                break;
            case quic_frame_handshake_done:
                // Figure 44: HANDSHAKE_DONE Frame Format
                break;
            default:
                ret = errorcode_t::unknown;
                break;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t quic_dump_frame(stream_t* s, tls_session* session, const binary_t frame, size_t& pos, tls_role_t role) {
    return quic_dump_frame(s, session, &frame[0], frame.size(), pos);
}

}  // namespace net
}  // namespace hotplace
