/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <math.h>

#include <sdk/net/http/http3/qpack.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

qpack_encoder::qpack_encoder() : http_header_compression() {
    // RFC 9204 Appendix A.  Static Table
    http_resource::get_instance()->for_each_qpack_static_table([&](uint32 index, const char* name, const char* value) -> void {
        _static_table.insert(std::make_pair(name, std::make_pair(value ? value : "", index)));
        _static_table_index.insert(std::make_pair(index, std::make_pair(name, value ? value : "")));
    });
}

return_t qpack_encoder::encode(http_header_compression_session* session, binary_t& target, const std::string& name, const std::string& value, uint32 flags) {
    return_t ret = errorcode_t::success;
    match_result_t state = match_result_t::not_matched;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t index = 0;

        if (0 == session->get_capacity()) {
            // no dynamic table
            flags &= ~(qpack_indexing | qpack_name_reference);
        }

        state = match(session, flags, name, value, index);  // flag effected - qpack_name_reference
        switch (state) {
            case match_result_t::all_matched:
            case match_result_t::all_matched_dynamic:
                if (match_result_t::all_matched == state) {
                    flags |= qpack_static;
                }
                if ((all_matched_dynamic == state) && (qpack_indexing & flags)) {
                    /**
                     *  RFC 9204
                     *      2.1.1.1.  Avoiding Prohibited Insertions
                     *
                     *                <-- Newer Entries          Older Entries -->
                     *                  (Larger Indices)       (Smaller Indices)
                     *      +--------+---------------------------------+----------+
                     *      | Unused |          Referenceable          | Draining |
                     *      | Space  |             Entries             | Entries  |
                     *      +--------+---------------------------------+----------+
                     *               ^                                 ^          ^
                     *               |                                 |          |
                     *         Insertion Point                 Draining Index  Dropping
                     *                                                          Point
                     *
                     *                  Figure 1: Draining Dynamic Table Entries
                     *
                     *      4.3.  Encoder Instructions
                     *      4.3.4.  Duplicate
                     *      B.4.  Duplicate Instruction, Stream Cancellation
                     *      - an encoded field section referencing the dynamic table entries including the duplicated entry
                     */
                    ret = errorcode_t::already_exist;
                    session->insert(name, value);  // duplicate
                    duplicate(target, index);
                } else {
                    if (qpack_postbase_index & flags) {
                        size_t postbase = 0;
                        size_t respsize = sizeof(size_t);
                        session->query(qpack_cmd_postbase_index, &index, sizeof(index), &postbase, respsize);
                        encode_index(target, flags, postbase);
                    } else {
                        encode_index(target, flags, index);
                    }
                }
                break;
            case match_result_t::key_matched:
            case match_result_t::key_matched_dynamic:
                // RFC 9204 4.3.2.  Insert with Name Reference
                if (match_result_t::key_matched == state) {
                    flags |= qpack_static;
                }
                if (qpack_indexing & flags) {
                    session->insert(name, value);
                }
                if (qpack_static & flags) {
                    // static table
                    encode_name_reference(session, target, flags, index, value);
                } else {
                    // dynamic table
                    size_t dropped = 0;
                    size_t respsize = sizeof(size_t);
                    session->query(qpack_cmd_dropped, nullptr, 0, &dropped, respsize);
                    if (dropped < index + 1) {
                        encode_name_reference(session, target, flags, index, value);
                    } else {
                        // invalid index evicted
                        // so encode literal name not name reference
                        encode_name_value(session, target, flags, name, value);
                    }
                }
                break;
            default:
                encode_name_value(session, target, flags, name, value);
                // RFC 9204 4.3.3.  Insert with Literal Name
                // ... adds an entry to the dynamic table ...
                if (qpack_indexing & flags) {
                    session->insert(name, value);
                }
                break;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t qpack_encoder::decode(http_header_compression_session* session, const byte_t* source, size_t size, size_t& pos, std::string& name, std::string& value,
                               uint32 flags) {
    return_t ret = errorcode_t::success;
    __try2 {
        name.clear();
        value.clear();

        if ((nullptr == session) || (nullptr == source)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (qpack_quic_stream_header & flags) {
            ret = decode_quic_stream_header(session, source, size, pos, name, value, flags);
        } else if (qpack_quic_stream_encoder & flags) {
            ret = decode_quic_stream_encoder(session, source, size, pos, name, value, flags);
        } else if (qpack_quic_stream_decoder & flags) {
            ret = decode_quic_stream_decoder(session, source, size, pos, name, value, flags);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t qpack_encoder::decode_quic_stream_encoder(http_header_compression_session* session, const byte_t* source, size_t size, size_t& pos, std::string& name,
                                                   std::string& value, uint32 flags) {
    return_t ret = errorcode_t::success;
    __try2 {
        if ((nullptr == session) || (nullptr == source)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        /**
         * RFC 9204
         *  4.3.  Encoder Instructions
         *   001   5+ - 4.3.1.  Set Dynamic Table Capacity
         *   1T    6+ - 4.3.2.  Insert with Name Reference / Figure 6: Insert Field Line -- Indexed Name
         *   01H   5+ - 4.3.3.  Insert with Literal Name / Figure 7: Insert Field Line -- New Name
         *   000   5+ - 4.3.4.  Duplicate / Figure 8: Duplicate
         */
        byte_t b = source[pos];
        uint8 mask = 0;
        uint8 prefix = 0;
        uint32 flags = 0;
        if (0x80 & b) {
            mask = 0xc0;
            prefix = 6;
            flags |= (qpack_layout_name_reference | qpack_indexing);
            if (0x40 & b) {
                flags |= qpack_static;
            }
        } else if (0x40 & b) {
            mask = 0x60;
            prefix = 5;
            flags |= (qpack_layout_name_value | qpack_indexing);
            if (0x20 & b) {
                flags |= qpack_huffman;
            }
        } else if (0x20 & b) {
            mask = 0x20;
            prefix = 5;
            flags |= qpack_layout_capacity;
        } else if (0xe0 & ~b) {
            mask = 0x00;
            prefix = 5;
            flags |= (qpack_layout_duplicate | qpack_indexing);
        }

        size_t i = 0;
        size_t idx = 0;
        if (qpack_layout_capacity & flags) {
            decode_int(source, pos, mask, prefix, i);
            session->set_capacity(i);
        } else if (qpack_layout_name_reference & flags) {
            decode_int(source, pos, mask, prefix, i);
            select(session, flags, i, name, value);
            decode_string(source, pos, flags, value);
        } else if (qpack_layout_name_value & flags) {
            decode_name_reference(source, pos, flags, mask, prefix, name);
            decode_string(source, pos, flags, value);
        } else if (qpack_layout_duplicate & flags) {
            decode_int(source, pos, mask, prefix, i);
            select(session, flags, i, name, value);
        }

        if (qpack_indexing & flags) {
            session->insert(name, value);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t qpack_encoder::decode_quic_stream_decoder(http_header_compression_session* session, const byte_t* source, size_t size, size_t& pos, std::string& name,
                                                   std::string& value, uint32 flags) {
    return_t ret = errorcode_t::success;
    __try2 {
        if ((nullptr == session) || (nullptr == source)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        /**
         * RFC 9204
         *  4.4.  Decoder Instructions
         *   1     7+ - 4.4.1.  Section Acknowledgment / Figure 9: Section Acknowledgment
         *   01    6+ - 4.4.2.  Stream Cancellation / Figure 10: Stream Cancellation
         *   00    6+ - 4.4.3.  Insert Count Increment / Figure 11: Insert Count Increment
         */
        byte_t b = source[pos];
        uint8 mask = 0;
        uint8 prefix = 0;
        uint32 flags = 0;
        if (0x80 & b) {
            mask = 0x80;
            prefix = 7;
            flags |= qpack_layout_ack;
        } else if (0x40 & b) {
            mask = 0x40;
            prefix = 6;
            flags |= qpack_layout_cancel;
        } else if (0xc0 & ~b) {
            mask = 0x00;
            prefix = 6;
            flags |= qpack_layout_inc;
        }

        size_t i = 0;
        size_t idx = 0;
        if (qpack_layout_ack & flags) {
            decode_int(source, pos, mask, prefix, i);  // stream id
        } else if (qpack_layout_cancel & flags) {
            decode_int(source, pos, mask, prefix, i);  // stream id
        } else if (qpack_layout_inc & flags) {
            decode_int(source, pos, mask, prefix, i);  // increment
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t qpack_encoder::decode_quic_stream_header(http_header_compression_session* session, const byte_t* source, size_t size, size_t& pos, std::string& name,
                                                  std::string& value, uint32 flags) {
    return_t ret = errorcode_t::success;
    __try2 {
        if ((nullptr == session) || (nullptr == source)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        /**
         * RFC 9204
         *  4.5.  Field Line Representations
         *  4.5.1.  Encoded Field Section Prefix / Figure 12: Encoded Field Section
         *        0   1   2   3   4   5   6   7
         *   +---+---+---+---+---+---+---+---+
         *   |   Required Insert Count (8+)  |
         *   +---+---------------------------+
         *   | S |      Delta Base (7+)      |
         *   +---+---------------------------+
         *   |      Encoded Field Lines    ...
         *   +-------------------------------+
         *      Figure 12: Encoded Field Section
         *
         *   1T    6+ - 4.5.2.  Indexed Field Line / Figure 13: Indexed Field Line
         *   0001  4+ - 4.5.3.  Indexed Field Line with Post-Base Index / Figure 14: Indexed Field Line with Post-Base Index
         *   01NT  4+ - 4.5.4.  Literal Field Line with Name Reference / Figure 15: Literal Field Line with Name Reference
         *   0000N 3+ - 4.5.5.  Literal Field Line with Post-Base Name Reference / Figure 16: Literal Field Line with Post-Base Name Reference
         *   001NH 3+ - 4.5.6.  Literal Field Line with Literal Name / Figure 17: Literal Field Line with Literal Name
         */
        size_t eic = 0;
        uint8 sign = 0;
        size_t deltabase = 0;
        size_t ric = 0;
        size_t base = 0;

        if (0 == pos) {
            decode_int(source, pos, 0, 8, eic);
            sign = 0x80 & source[pos];
            decode_int(source, pos, 0x80, 7, deltabase);

            qpack_eic2ric(session->get_capacity(), session->get_entries(), eic, sign, deltabase, ric, base);

            auto entries = session->get_entries();
            if (ric != entries) {
                ret = errorcode_t::mismatch;
                __leave2;
            }
        } else if (pos >= 2) {
            byte_t b = source[pos];
            uint8 mask = 0;
            uint8 prefix = 0;
            uint32 flags = 0;
            if (0x80 & b) {
                // index
                mask = 0xc0;
                prefix = 6;
                flags |= qpack_layout_index;
                if (0x40 & b) {
                    flags |= qpack_static;
                }
            } else if (0x40 & b) {
                // name reference
                mask = 0x70;
                prefix = 4;
                flags |= qpack_layout_name_reference;
                if (0x20 & b) {
                    flags |= qpack_intermediary;
                }
                if (0x10 & b) {
                    flags |= qpack_static;
                }
            } else if (0x20 & b) {
                // name value
                mask = 0x38;
                prefix = 3;
                flags |= qpack_layout_name_value;
                if (0x10 & b) {
                    flags |= qpack_intermediary;
                }
                if (0x08 & b) {
                    flags |= qpack_huffman;
                }
            } else if (0x10 & b) {
                // post-base index
                mask = 0x10;
                prefix = 4;
                flags |= (qpack_layout_index | qpack_postbase_index);
            } else if (0xf0 & ~b) {
                // post-base name reference
                mask = 0x08;
                prefix = 3;
                flags |= (qpack_layout_name_reference | qpack_postbase_index);
                if (0x08 & b) {
                    flags |= qpack_intermediary;
                }
            }

            size_t i = 0;
            size_t idx = 0;
            if (qpack_layout_index & flags) {
                decode_int(source, pos, mask, prefix, i);
                select(session, flags, i, name, value);
            } else if (qpack_layout_name_reference & flags) {
                decode_int(source, pos, mask, prefix, i);
                select(session, flags, i, name, value);
                decode_string(source, pos, flags, value);
            } else if (qpack_layout_name_value & flags) {
                pos++;
                decode_string(source, pos, flags, name);
                decode_string(source, pos, flags, value);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t qpack_encoder::insert(http_header_compression_session* session, binary_t& target, const std::string& name, const std::string& value, uint32 flags) {
    return encode(session, target, name, value, flags | qpack_indexing);
}

return_t qpack_encoder::sync(http_header_compression_session* session, binary_t& target, uint32 flags) {
    return_t ret = errorcode_t::success;
    /**
     * RFC 9204 4.5.1.  Encoded Field Section Prefix
     *
     *    0   1   2   3   4   5   6   7
     *  +---+---+---+---+---+---+---+---+
     *  |   Required Insert Count (8+)  |
     *  +---+---------------------------+
     *  | S |      Delta Base (7+)      |
     *  +---+---------------------------+
     *  |      Encoded Field Lines    ...
     *  +-------------------------------+
     *
     *  Figure 12: Encoded Field Section
     *
     * 4.5.1.1.  Required Insert Count
     */
    if (session) {
        size_t capacity = session->get_capacity();
        size_t ric = session->get_entries();
        size_t base = 0;
        size_t eic = 0;
        bool sign = true;
        size_t deltabase = 0;

        if (qpack_postbase_index & flags) {
            base = 0;
        } else {
            base = ric;
        }

        qpack_ric2eic(capacity, ric, base, eic, sign, deltabase);

        binary_t temp;
        temp.push_back(eic);
        uint8 mask = sign ? 0x80 : 0x00;
        uint8 prefix = 7;
        encode_int(temp, mask, prefix, deltabase);
        target.insert(target.begin(), temp.begin(), temp.end());
    }

    return ret;
}

qpack_encoder& qpack_encoder::encode_header(http_header_compression_session* session, binary_t& target, const std::string& name, const std::string& value,
                                            uint32 flags) {
    encode(session, target, name, value, flags);
    return *this;
}

qpack_encoder& qpack_encoder::decode_header(http_header_compression_session* session, const byte_t* source, size_t size, size_t& pos, std::string& name,
                                            std::string& value) {
    decode(session, source, size, pos, name, value);
    return *this;
}

qpack_encoder& qpack_encoder::encode_index(binary_t& target, uint32 flags, size_t index) {
    uint8 mask = 0;
    uint8 prefix = 0;

    if (qpack_postbase_index & flags) {
        /**
         * RFC 9204 4.5.3.  Indexed Field Line with Post-Base Index
         *
         *    0   1   2   3   4   5   6   7
         *  +---+---+---+---+---+---+---+---+
         *  | 0 | 0 | 0 | 1 |  Index (4+)   |
         *  +---+---+---+---+---------------+
         *
         *  Figure 14: Indexed Field Line with Post-Base Index
         */
        mask = 0x10;
        prefix = 4;
    } else {
        /**
         * RFC 9204 4.5.2.  Indexed Field Line
         *
         *    0   1   2   3   4   5   6   7
         *  +---+---+---+---+---+---+---+---+
         *  | 1 | T |      Index (6+)       |
         *  +---+---+-----------------------+
         *
         *  Figure 13: Indexed Field Line
         *
         */
        mask = 0x80;
        prefix = 6;
        if (qpack_static & flags) {
            mask |= 0x40;
        }
    }

    encode_int(target, mask, prefix, index);

    return *this;
}

qpack_encoder& qpack_encoder::encode_name_reference(http_header_compression_session* session, binary_t& target, uint32 flags, size_t index,
                                                    const std::string& value) {
    if (session) {
        uint8 mask = 0;
        uint8 prefix = 0;

        if (qpack_indexing & flags) {
            /**
             * RFC 9204 4.3.2.  Insert with Name Reference
             *
             *    0   1   2   3   4   5   6   7
             *  +---+---+---+---+---+---+---+---+
             *  | 1 | T |    Name Index (6+)    |
             *  +---+---+-----------------------+
             *  | H |     Value Length (7+)     |
             *  +---+---------------------------+
             *  |  Value String (Length bytes)  |
             *  +-------------------------------+
             *
             *  Figure 6: Insert Field Line -- Indexed Name
             */
            mask = 0x80;
            if (qpack_intermediary & flags) {
                mask |= 0x40;
            }
            prefix = 6;
        } else {
            if (qpack_postbase_index & flags) {
                /**
                 *
                 * RFC 9204 4.5.5.  Literal Field Line with Post-Base Name Reference
                 *
                 *    0   1   2   3   4   5   6   7
                 *  +---+---+---+---+---+---+---+---+
                 *  | 0 | 0 | 0 | 0 | N |NameIdx(3+)|
                 *  +---+---+---+---+---+-----------+
                 *  | H |     Value Length (7+)     |
                 *  +---+---------------------------+
                 *  |  Value String (Length bytes)  |
                 *  +-------------------------------+
                 *
                 *  Figure 16: Literal Field Line with Post-Base Name Reference
                 */
                mask = 0x00;
                if (qpack_intermediary & flags) {
                    mask |= 0x08;
                }
                prefix = 3;
            } else {
                /**
                 * RFC 9204 4.5.4.  Literal Field Line with Name Reference
                 * RFC 9204 B.1.  Literal Field Line with Name Reference
                 *
                 *    0   1   2   3   4   5   6   7
                 *  +---+---+---+---+---+---+---+---+
                 *  | 0 | 1 | N | T |Name Index (4+)|
                 *  +---+---+---+---+---------------+
                 *  | H |     Value Length (7+)     |
                 *  +---+---------------------------+
                 *  |  Value String (Length bytes)  |
                 *  +-------------------------------+
                 *
                 *  Figure 15: Literal Field Line with Name Reference
                 */
                mask = 0x40;
                if (qpack_intermediary & flags) {
                    mask |= 0x20;
                }
                if (qpack_static & flags) {
                    mask |= 0x10;
                }
                prefix = 4;
            }
        }

        encode_int(target, mask, prefix, index);
        encode_string(target, flags, value);
    }
    return *this;
}

qpack_encoder& qpack_encoder::encode_name_value(http_header_compression_session* session, binary_t& target, uint32 flags, const std::string& name,
                                                const std::string& value) {
    if (session) {
        uint8 mask = 0;
        uint8 prefix = 0;

        if (qpack_indexing & flags) {
            /**
             * RFC 9204 4.3.3.  Insert with Literal Name
             *
             *    0   1   2   3   4   5   6   7
             *  +---+---+---+---+---+---+---+---+
             *  | 0 | 1 | H | Name Length (5+)  |
             *  +---+---+---+-------------------+
             *  |  Name String (Length bytes)   |
             *  +---+---------------------------+
             *  | H |     Value Length (7+)     |
             *  +---+---------------------------+
             *  |  Value String (Length bytes)  |
             *  +-------------------------------+
             *
             *  Figure 7: Insert Field Line -- New Name
             */

            mask = 0x40;
            if (qpack_huffman & flags) {
                mask |= 0x20;
            }
            prefix = 5;
        } else {
            /**
             * RFC 9204 4.5.6.  Literal Field Line with Literal Name
             *
             *    0   1   2   3   4   5   6   7
             *  +---+---+---+---+---+---+---+---+
             *  | 0 | 0 | 1 | N | H |NameLen(3+)|
             *  +---+---+---+---+---+-----------+
             *  |  Name String (Length bytes)   |
             *  +---+---------------------------+
             *  | H |     Value Length (7+)     |
             *  +---+---------------------------+
             *  |  Value String (Length bytes)  |
             *  +-------------------------------+
             *
             *  Figure 17: Literal Field Line with Literal Name
             */

            mask = 0x20;
            if (qpack_intermediary & flags) {
                mask |= 0x10;
            }
            if (qpack_huffman & flags) {
                mask |= 0x80;
            }
            prefix = 3;
        }

        encode_int(target, mask, prefix, name.size());
        if (qpack_huffman & flags) {
            _huffcode.encode(target, name.c_str(), name.size());
        } else {
            target.insert(target.end(), name.begin(), name.end());
        }
        encode_string(target, flags, value.c_str(), value.size());
    }

    return *this;
}

qpack_encoder& qpack_encoder::duplicate(binary_t& target, size_t index) {
    /**
     * RFC 9204 4.3.4.  Duplicate
     *
     *    0   1   2   3   4   5   6   7
     *  +---+---+---+---+---+---+---+---+
     *  | 0 | 0 | 0 |    Index (5+)     |
     *  +---+---+---+-------------------+
     *
     *  Figure 8: Duplicate
     */
    uint8 mask = 0x00;
    uint8 prefix = 5;
    encode_int(target, mask, prefix, index);
    return *this;
}

qpack_encoder& qpack_encoder::ack(binary_t& target, uint32 streamid) {
    /**
     * RFC 9204 4.4.1.  Section Acknowledgment
     *
     *    0   1   2   3   4   5   6   7
     *  +---+---+---+---+---+---+---+---+
     *  | 1 |      Stream ID (7+)       |
     *  +---+---------------------------+
     *
     *  Figure 9: Section Acknowledgment
     */
    uint8 mask = 0x80;
    uint8 prefix = 7;
    encode_int(target, mask, prefix, streamid);
    return *this;
}

qpack_encoder& qpack_encoder::cancel(binary_t& target, uint32 streamid) {
    /**
     * RFC 9204 4.4.2.  Stream Cancellation
     *
     *    0   1   2   3   4   5   6   7
     *  +---+---+---+---+---+---+---+---+
     *  | 0 | 1 |     Stream ID (6+)    |
     *  +---+---+-----------------------+
     *
     *  Figure 10: Stream Cancellation
     */
    uint8 mask = 0x40;
    uint8 prefix = 6;
    encode_int(target, mask, prefix, streamid);
    return *this;
}

qpack_encoder& qpack_encoder::increment(binary_t& target, size_t inc) {
    /**
     * RFC 9204 4.4.3.  Insert Count Increment
     *
     *    0   1   2   3   4   5   6   7
     *  +---+---+---+---+---+---+---+---+
     *  | 0 | 0 |     Increment (6+)    |
     *  +---+---+-----------------------+
     *
     *  Figure 11: Insert Count Increment
     */
    uint8 mask = 0x00;
    uint8 prefix = 6;
    encode_int(target, mask, prefix, inc);
    return *this;
}

}  // namespace net
}  // namespace hotplace
