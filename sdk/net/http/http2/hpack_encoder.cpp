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

hpack_encoder::hpack_encoder() {
    // RFC 7541 Appendix B. Huffman Code
    _huffcode.imports(_h2hcodes);

    // RFC 7541 Appendix A.  Static Table Definition
    // if (_static_table.empty()) ...
    http_resource::get_instance()->for_each_hpack_static_table([&](uint32 index, const char* name, const char* value) -> void {
        _static_table.insert(std::make_pair(name, std::make_pair(value ? value : "", index)));
        _static_table_index.insert(std::make_pair(index, std::make_pair(name, value ? value : "")));
    });
}

hpack_encoder& hpack_encoder::encode_int(binary_t& target, uint8 mask, uint8 prefix, size_t value) {
    hc_encode_int(target, mask, prefix, value);
    return *this;
}

hpack_encoder& hpack_encoder::encode_string(binary_t& target, uint32 flags, const char* value, size_t size) {
    hc_encode_string(_huffcode, target, flags, value, size);
    return *this;
}

hpack_encoder& hpack_encoder::encode_string(binary_t& target, uint32 flags, const std::string& value) {
    hc_encode_string(_huffcode, target, flags, value.c_str(), value.size());
    return *this;
}

hpack_encoder& hpack_encoder::encode_index(binary_t& target, uint8 index) {
    // RFC 7541 Figure 5: Indexed Header Field
    //
    //     0   1   2   3   4   5   6   7
    //   +---+---+---+---+---+---+---+---+
    //   | 1 |        Index (7+)         |
    //   +---+---------------------------+

    hc_encode_int(target, 0x80, 7, index);
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
            hc_encode_int(target, 0x40, 6, index);
        } else if (hpack_wo_indexing & flags) {
            // RFC 7541 Figure 8: Literal Header Field without Indexing -- Indexed Name
            //
            //     0   1   2   3   4   5   6   7
            //   +---+---+---+---+---+---+---+---+
            //   | 0 | 0 | 0 | 0 |  Index (4+)   |
            //   +---+---+-----------------------+
            hc_encode_int(target, 0x00, 4, index);
        } else if (hpack_never_indexed & flags) {
            // RFC 7541 Figure 10: Literal Header Field Never Indexed -- Indexed Name
            //
            //     0   1   2   3   4   5   6   7
            //   +---+---+---+---+---+---+---+---+
            //   | 0 | 0 | 0 | 1 |  Index (4+)   |
            //   +---+---+-----------------------+
            hc_encode_int(target, 0x10, 4, index);
        } else {
            __leave2;
        }

        //   +-------------------------------+
        //   | H |     Value Length (7+)     |
        //   +---+---------------------------+
        //   | Value String (Length octets)  |
        //   +-------------------------------+
        hc_encode_string(_huffcode, target, flags, value, size);
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
        hc_encode_string(_huffcode, target, flags, name, namelen);
        hc_encode_string(_huffcode, target, flags, value, valuelen);
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

hpack_encoder& hpack_encoder::decode_int(const byte_t* p, size_t& pos, uint8 mask, uint8 prefix, size_t& value) {
    hc_decode_int(p, pos, mask, prefix, value);
    return *this;
}

hpack_encoder& hpack_encoder::decode_string(const byte_t* p, size_t& pos, uint8 flags, std::string& value) {
    hc_decode_string(_huffcode, p, pos, flags, value);
    return *this;
}

match_result_t hpack_encoder::match(hpack_session* session, const std::string& name, const std::string& value, size_t& index) {
    match_result_t state = match_result_t::not_matched;
    index = 0;

    if (session) {
        state = session->match(name, value, index);
        if (match_result_t::all_matched == state) {
            index += _static_table.size() + 1;
        }
    }
    if (match_result_t::not_matched == state) {
        static_table_t::iterator iter;
        static_table_t::iterator liter;
        static_table_t::iterator uiter;

        liter = _static_table.lower_bound(name);
        uiter = _static_table.upper_bound(name);

        for (iter = liter; iter != uiter; iter++) {
            if (iter == liter) {
                index = iter->second.second;  // :path: /sample/path
                state = match_result_t::key_matched;
            }
            if (value == iter->second.first) {
                index = iter->second.second;
                state = match_result_t::all_matched;
                break;
            }
        }
    }
    return state;
}

return_t hpack_encoder::select(hpack_session* session, uint32 flags, size_t index, std::string& name, std::string& value) {
    return_t ret = errorcode_t::success;
    __try2 {
        name.clear();
        value.clear();

        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (index > _static_table.size()) {
            index -= (_static_table.size() + 1);
            ret = session->select(flags, index, name, value);
        } else {
            static_table_index_t::iterator iter = _static_table_index.find(index);
            if (_static_table_index.end() == iter) {
                ret = errorcode_t::not_found;
                __leave2;
            } else {
                name = iter->second.first;
                if ((hpack_index | hpack_name_value) & flags) {
                    value = iter->second.second;
                }
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t hpack_encoder::insert(hpack_session* session, const std::string& name, const std::string& value) {
    //  RFC 7541 Figure 1: Index Address Space
    //
    //   <----------  Index Address Space ---------->
    //   <-- Static  Table -->  <-- Dynamic Table -->
    //   +---+-----------+---+  +---+-----------+---+
    //   | 1 |    ...    | s |  |s+1|    ...    |s+k|
    //   +---+-----------+---+  +---+-----------+---+
    //                          ^                   |
    //                          |                   V
    //                   Insertion Point      Dropping Point
    //
    //               Figure 1: Index Address Space
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        session->insert(name, value);
    }
    __finally2 {
        // do nothing
    }
    return ret;
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
            hc_decode_int(source, pos, mask, prefix, i);
            select(session, flags, i, name, value);
        } else if (hpack_indexed_name & flags) {
            hc_decode_int(source, pos, mask, prefix, i);
            select(session, flags, i, name, value);
            hc_decode_string(_huffcode, source, pos, flags, value);
        } else if (hpack_name_value & flags) {
            pos++;
            hc_decode_string(_huffcode, source, pos, flags, name);
            hc_decode_string(_huffcode, source, pos, flags, value);
        }

        if (hpack_indexing & flags) {
            if (all_matched != match(session, name, value, idx)) {
                insert(session, name, value);
            }
        }
    }
    return *this;
}

}  // namespace net
}  // namespace hotplace
