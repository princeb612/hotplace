/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

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

        state = match(session, flags, name, value, index);
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
                    size_t postbase = 0;
                    size_t respsize = sizeof(size_t);
                    session->query(qpack_cmd_postbase_index, &index, sizeof(index), &postbase, respsize);
                    if (qpack_postbase_index & flags) {
                        encode_index(target, flags, postbase);
                    } else {
                        encode_index(target, flags, index);
                    }
                }
                break;
            case match_result_t::key_matched:
            case match_result_t::key_matched_dynamic:
                if (match_result_t::key_matched == state) {
                    flags |= qpack_static;
                }
                encode_name_reference(session, target, flags, index, value);
                // RFC 9204 4.3.2.  Insert with Name Reference
                if (qpack_indexing & flags) {
                    session->insert(name, value);
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

return_t qpack_encoder::decode(http_header_compression_session* session, const byte_t* source, size_t size, size_t& pos, std::string& name,
                               std::string& value) {
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
         *   1T    6+ - 4.3.2.  Insert with Name Reference
         *   01H   5+ - 4.3.3.  Insert with Literal Name
         *   000   5+ - 4.3.4.  Duplicate
         *  4.4.  Decoder Instructions
         *   1     7+ - 4.4.1.  Section Acknowledgment
         *   01    6+ - 4.4.2.  Stream Cancellation
         *   00    6+ - 4.4.3.  Insert Count Increment
         *  4.5.  Field Line Representations
         *  4.5.1.  Encoded Field Section Prefix
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
         *   1T    6+ - 4.5.2.  Indexed Field Line / Figure 13
         *   0001  4+ - 4.5.3.  Indexed Field Line with Post-Base Index / Figure 14
         *   01NT  4+ - 4.5.4.  Literal Field Line with Name Reference / Figure 15
         *   0000N 3+ - 4.5.5.  Literal Field Line with Post-Base Name Reference / Figure 16
         *   001NH 3+ - 4.5.6.  Literal Field Line with Literal Name / Figure 17
         */
        byte_t b = source[pos];
        uint8 mask = 0;
        uint8 prefix = 0;
        uint32 flags = 0;
        if (0x80 & b) {
            // index
        } else if (0x10 & b) {
            // post-base index
        } else if (0x40 & b) {
            // name reference
        } else if (0xf0 & ~b) {
            // post-base name reference
        } else if (0x20 & b) {
            // name value
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
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
        size_t ric = 0;
        size_t base = 0;
        size_t eic = 0;
        bool sign = true;
        size_t deltabase = 0;

        size_t respsize = sizeof(ric);
        session->query(qpack_cmd_ric, nullptr, 0, &ric, respsize);

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

return_t qpack_encoder::insert(http_header_compression_session* session, binary_t& target, const std::string& name, const std::string& value, uint32 flags) {
    return encode(session, target, name, value, flags | qpack_indexing);
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
