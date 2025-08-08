/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/http/compression/http_dynamic_table.hpp>
#include <sdk/net/http/hpack/hpack_encoder.hpp>
#include <sdk/net/http/hpack/hpack_static_table.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

hpack_encoder::hpack_encoder() : http_header_compression() {}

return_t hpack_encoder::encode(http_dynamic_table* dyntable, binary_t& target, const std::string& name, const std::string& value, uint32 flags) {
    return_t ret = errorcode_t::success;
    match_result_t state = match_result_t::not_matched;
    __try2 {
        if (nullptr == dyntable) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t index = 0;

        auto statable = hpack_static_table::get_instance();
        state = matchall(statable, dyntable, 0, name, value, index);  // set flags = 0
        switch (state) {
            case match_result_t::all_matched:
            case match_result_t::all_matched_dynamic:
                encode_index(target, index);
                break;
            case match_result_t::key_matched:
            case match_result_t::key_matched_dynamic:
                encode_indexed_name(target, flags, index, value);
                if (hpack_indexing & flags) {
                    dyntable->insert(name, value);
                    dyntable->commit();
                }
                break;
            default:
                encode_name_value(target, flags, name, value);
                if (hpack_indexing & flags) {
                    dyntable->insert(name, value);
                    dyntable->commit();
                }
                break;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t hpack_encoder::decode(http_dynamic_table* dyntable, const byte_t* source, size_t size, size_t& pos, std::string& name, std::string& value) {
    return_t ret = errorcode_t::success;
    __try2 {
        if ((nullptr == dyntable) || (nullptr == source)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        /**
         * RFC 7541
         *  6.  Binary Format
         *   1     7+ - 6.1.  Indexed Header Field Representation
         *   01    6+ - 6.2.1.  Literal Header Field with Incremental Indexing / Figure 6
         *   01000000 - 6.2.1.  Literal Header Field with Incremental Indexing / Figure 7
         *   0000  4+ - 6.2.2.  Literal Header Field without Indexing / Figure 8
         *   00000000 - 6.2.2.  Literal Header Field without Indexing / Figure 9
         *   0001  4+ - 6.2.3.  Literal Header Field Never Indexed / Figure 10
         *   00010000 - 6.2.3.  Literal Header Field Never Indexed / Figure 11
         *   001   5+ - 6.3.  Dynamic Table Size Update
         */
        byte_t b = source[pos];
        uint8 mask = 0;
        uint8 prefix = 0;
        uint32 flags = 0;
        if (0x80 & b) {
            // index
            mask = 0x80;
            prefix = 7;
            flags |= hpack_layout_index;
        } else if (0x40 & b) {
            // indexing
            mask = 0x40;
            prefix = 6;
            flags |= hpack_indexing;
            if (0x3f & b) {
                flags |= hpack_layout_indexed_name;
            } else {
                flags |= hpack_layout_name_value;
            }
        } else if (0xf0 & ~b) {
            // without indexing
            mask = 0x00;
            prefix = 4;
            flags |= hpack_wo_indexing;
            if (0x0f & b) {
                flags |= hpack_layout_indexed_name;
            } else {
                flags |= hpack_layout_name_value;
            }
        } else if (0x10 & b) {
            // never indexed
            mask = 0x10;
            prefix = 4;
            flags |= hpack_never_indexed;
            if (0x0f & b) {
                flags |= hpack_layout_indexed_name;
            } else {
                flags |= hpack_layout_name_value;
            }
        }

        // do not handle hpack_layout_capacity here
        // HTTP2 SETTINGS frame SETTINGS_HEADER_TABLE_SIZE (0x1)
        // see http2_session::consume

        auto statable = hpack_static_table::get_instance();

        size_t i = 0;
        size_t idx = 0;
        if (hpack_layout_index & flags) {
            decode_int(source, pos, mask, prefix, i);
            selectall(statable, dyntable, flags, i, name, value);
        } else if (hpack_layout_indexed_name & flags) {
            decode_int(source, pos, mask, prefix, i);
            selectall(statable, dyntable, flags, i, name, value);
            decode_string(source, pos, flags, value);
        } else if (hpack_layout_name_value & flags) {
            // RFC 7541 Figure 7: Literal Header Field with Incremental Indexing -- New Name
            // RFC 7541 Figure 9: Literal Header Field without Indexing -- New Name
            // RFC 7541 Figure 11: Literal Header Field Never Indexed -- New Name
            pos++;
            decode_string(source, pos, flags, name);
            decode_string(source, pos, flags, value);
        }

        if (hpack_indexing & flags) {
            auto r = matchall(statable, dyntable, 0, name, value, idx);
            switch (r) {
                case all_matched:
                case all_matched_dynamic:
                    break;
                default:
                    dyntable->insert(name, value);
                    break;
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

hpack_encoder& hpack_encoder::encode_header(http_dynamic_table* dyntable, binary_t& target, const std::string& name, const std::string& value, uint32 flags) {
    encode(dyntable, target, name, value, flags);
    return *this;
}

hpack_encoder& hpack_encoder::decode_header(http_dynamic_table* dyntable, const byte_t* source, size_t size, size_t& pos, std::string& name,
                                            std::string& value) {
    decode(dyntable, source, size, pos, name, value);
    return *this;
}

hpack_encoder& hpack_encoder::encode_index(binary_t& target, size_t index) {
    // RFC 7541 Figure 5: Indexed Header Field
    //
    //     0   1   2   3   4   5   6   7
    //   +---+---+---+---+---+---+---+---+
    //   | 1 |        Index (7+)         |
    //   +---+---------------------------+

    encode_int(target, 0x80, 7, index);
    return *this;
}

hpack_encoder& hpack_encoder::encode_indexed_name(binary_t& target, uint32 flags, size_t index, const char* value) {
    if (value) {
        encode_indexed_name(target, flags, index, value, strlen(value));
    }
    return *this;
}

hpack_encoder& hpack_encoder::encode_indexed_name(binary_t& target, uint32 flags, size_t index, const char* value, size_t size) {
    __try2 {
        if (nullptr == value) {
            __leave2;
        }

        if (hpack_indexing & flags) {
            // RFC 7541 Figure 6: Literal Header Field with Incremental Indexing -- Indexed Name
            //
            //     0   1   2   3   4   5   6   7
            //   +---+---+---+---+---+---+---+---+
            //   | 0 | 1 |      Index (6+)       |
            //   +---+---+-----------------------+
            encode_int(target, 0x40, 6, index);
        } else if (hpack_wo_indexing & flags) {
            // RFC 7541 Figure 8: Literal Header Field without Indexing -- Indexed Name
            //
            //     0   1   2   3   4   5   6   7
            //   +---+---+---+---+---+---+---+---+
            //   | 0 | 0 | 0 | 0 |  Index (4+)   |
            //   +---+---+-----------------------+
            encode_int(target, 0x00, 4, index);
        } else if (hpack_never_indexed & flags) {
            // RFC 7541 Figure 10: Literal Header Field Never Indexed -- Indexed Name
            //
            //     0   1   2   3   4   5   6   7
            //   +---+---+---+---+---+---+---+---+
            //   | 0 | 0 | 0 | 1 |  Index (4+)   |
            //   +---+---+-----------------------+
            encode_int(target, 0x10, 4, index);
        } else {
            __leave2;
        }

        //   +-------------------------------+
        //   | H |     Value Length (7+)     |
        //   +---+---------------------------+
        //   | Value String (Length octets)  |
        //   +-------------------------------+
        encode_string(target, flags, value, size);
    }
    __finally2 {
        // do nothing
    }
    return *this;
}

hpack_encoder& hpack_encoder::encode_indexed_name(binary_t& target, uint32 flags, size_t index, const std::string& value) {
    encode_indexed_name(target, flags, index, value.c_str(), value.size());
    return *this;
}

hpack_encoder& hpack_encoder::encode_name_value(binary_t& target, uint32 flags, const char* name, const char* value) {
    if (name && value) {
        encode_name_value(target, flags, name, strlen(name), value, strlen(value));
    }
    return *this;
}

hpack_encoder& hpack_encoder::encode_name_value(binary_t& target, uint32 flags, const char* name, size_t namelen, const char* value, size_t valuelen) {
    __try2 {
        if (nullptr == name || nullptr == value) {
            __leave2;
        }

        if (hpack_indexing & flags) {
            // RFC 7541 Figure 7: Literal Header Field with Incremental Indexing -- New Name
            //
            //     0   1   2   3   4   5   6   7
            //   +---+---+---+---+---+---+---+---+
            //   | 0 | 1 |           0           |
            //   +---+---+-----------------------+
            target.insert(target.end(), 0x40);
        } else if (hpack_wo_indexing & flags) {
            // RFC 7541 Figure 9: Literal Header Field without Indexing -- New Name
            //
            //     0   1   2   3   4   5   6   7
            //   +---+---+---+---+---+---+---+---+
            //   | 0 | 0 | 0 | 0 |       0       |
            //   +---+---+-----------------------+
            target.insert(target.end(), 0);
        } else if (hpack_never_indexed & flags) {
            // RFC 7541 Figure 11: Literal Header Field Never Indexed -- New Name
            //
            //     0   1   2   3   4   5   6   7
            //   +---+---+---+---+---+---+---+---+
            //   | 0 | 0 | 0 | 1 |       0       |
            //   +---+---+-----------------------+
            target.insert(target.end(), 0x10);
        } else {
            __leave2;
        }

        //   +---+---------------------------+
        //   | H |     Name Length (7+)      |
        //   +---+---------------------------+
        //   |  Name String (Length octets)  |
        //   +---+---------------------------+
        //   | H |     Value Length (7+)     |
        //   +---+---------------------------+
        //   | Value String (Length octets)  |
        //   +-------------------------------+
        encode_string(target, flags, name, namelen);
        encode_string(target, flags, value, valuelen);
    }
    __finally2 {
        // do nothing
    }
    return *this;
}

hpack_encoder& hpack_encoder::encode_name_value(binary_t& target, uint32 flags, const std::string& name, const std::string& value) {
    encode_name_value(target, flags, name.c_str(), name.size(), value.c_str(), value.size());
    return *this;
}

}  // namespace net
}  // namespace hotplace
