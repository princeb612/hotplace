/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/http/http2/hpack.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

hpack_encoder::hpack_encoder() : http_header_compression() {
    // RFC 7541 Appendix A.  Static Table Definition
    // if (_static_table.empty()) ...
    http_resource::get_instance()->for_each_hpack_static_table([&](uint32 index, const char* name, const char* value) -> void {
        _static_table.insert(std::make_pair(name, std::make_pair(value ? value : "", index)));
        _static_table_index.insert(std::make_pair(index, std::make_pair(name, value ? value : "")));
    });
}

hpack_encoder& hpack_encoder::encode_index(binary_t& target, uint8 index) {
    // RFC 7541 Figure 5: Indexed Header Field
    //
    //     0   1   2   3   4   5   6   7
    //   +---+---+---+---+---+---+---+---+
    //   | 1 |        Index (7+)         |
    //   +---+---------------------------+

    encode_int(target, 0x80, 7, index);
    return *this;
}

hpack_encoder& hpack_encoder::encode_indexed_name(binary_t& target, uint32 flags, uint8 index, const char* value) {
    if (value) {
        encode_indexed_name(target, flags, index, value, strlen(value));
    }
    return *this;
}

hpack_encoder& hpack_encoder::encode_indexed_name(binary_t& target, uint32 flags, uint8 index, const char* value, size_t size) {
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

hpack_encoder& hpack_encoder::encode_indexed_name(binary_t& target, uint32 flags, uint8 index, const std::string& value) {
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

hpack_encoder& hpack_encoder::encode_header(hpack_session* session, binary_t& target, const std::string& name, const std::string& value, uint32 flags) {
    match_result_t state = match_result_t::not_matched;
    if (session) {
        size_t index = 0;

        state = match(session, name, value, index);
        switch (state) {
            case match_result_t::all_matched:
                encode_index(target, index);
                break;
            case match_result_t::key_matched:
                encode_indexed_name(target, flags, index, value);
                if (hpack_indexing & flags) {
                    session->insert(name, value);
                }
                break;
            default:
                encode_name_value(target, flags, name, value);
                if (hpack_indexing & flags) {
                    session->insert(name, value);
                }
                break;
        }
    }
    return *this;
}

hpack_encoder& hpack_encoder::decode_header(hpack_session* session, const byte_t* source, size_t size, size_t& pos, std::string& name, std::string& value) {
    if (session && source) {
        byte_t b = source[pos];
        uint8 mask = 0;
        uint8 prefix = 0;
        uint32 flags = 0;
        if (0x80 & b) {
            // index
            mask = 0x80;
            prefix = 7;
            flags |= hpack_index;
        } else if (0x40 & b) {
            // indexing
            mask = 0x40;
            prefix = 6;
            flags |= hpack_indexing;
            if (0x3f & b) {
                flags |= hpack_indexed_name;
            } else {
                flags |= hpack_name_value;
            }
        } else if (0xf0 & ~b) {
            // without indexing
            mask = 0x00;
            prefix = 4;
            flags |= hpack_wo_indexing;
            if (0x0f & b) {
                flags |= hpack_indexed_name;
            } else {
                flags |= hpack_name_value;
            }
        } else if (0x10 & b) {
            // never indexed
            mask = 0x10;
            prefix = 4;
            flags |= hpack_never_indexed;
            if (0x0f & b) {
                flags |= hpack_indexed_name;
            } else {
                flags |= hpack_name_value;
            }
        }

        size_t i = 0;
        size_t idx = 0;
        if (hpack_index & flags) {
            decode_int(source, pos, mask, prefix, i);
            select(session, flags, i, name, value);
        } else if (hpack_indexed_name & flags) {
            decode_int(source, pos, mask, prefix, i);
            select(session, flags, i, name, value);
            decode_string(source, pos, flags, value);
        } else if (hpack_name_value & flags) {
            pos++;
            decode_string(source, pos, flags, name);
            decode_string(source, pos, flags, value);
        }

        if (hpack_indexing & flags) {
            if (all_matched != match(session, name, value, idx)) {
                session->insert(name, value);
            }
        }
    }
    return *this;
}

}  // namespace net
}  // namespace hotplace
