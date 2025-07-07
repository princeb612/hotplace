/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 2068 Hypertext Transfer Protocol -- HTTP/1.1
 *  RFC 2616 Hypertext Transfer Protocol -- HTTP/1.1
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/http/http2/types.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

void http_resource::doload_resources_h2() {
    if (_h2_frame_names.empty()) {
        _h2_frame_names.insert(std::make_pair(h2_frame_t::h2_frame_data, "DATA"));
        _h2_frame_names.insert(std::make_pair(h2_frame_t::h2_frame_headers, "HEADERS"));
        _h2_frame_names.insert(std::make_pair(h2_frame_t::h2_frame_priority, "PRIORITY"));
        _h2_frame_names.insert(std::make_pair(h2_frame_t::h2_frame_rst_stream, "RST_STREAM"));
        _h2_frame_names.insert(std::make_pair(h2_frame_t::h2_frame_settings, "SETTINGS"));
        _h2_frame_names.insert(std::make_pair(h2_frame_t::h2_frame_push_promise, "PUSH_PROMISE"));
        _h2_frame_names.insert(std::make_pair(h2_frame_t::h2_frame_ping, "PING"));
        _h2_frame_names.insert(std::make_pair(h2_frame_t::h2_frame_goaway, "GOAWAY"));
        _h2_frame_names.insert(std::make_pair(h2_frame_t::h2_frame_window_update, "WINDOW_UPDATE"));
        _h2_frame_names.insert(std::make_pair(h2_frame_t::h2_frame_continuation, "CONTINUATION"));
        _h2_frame_names.insert(std::make_pair(h2_frame_t::h2_frame_altsvc, "ALTSVC"));
    }

    if (_h2_frame_flags.empty()) {
        _h2_frame_flags.insert(std::make_pair(h2_flag_t::h2_flag_end_stream, "END_STREAM"));
        _h2_frame_flags.insert(std::make_pair(h2_flag_t::h2_flag_end_headers, "END_HEADERS"));
        _h2_frame_flags.insert(std::make_pair(h2_flag_t::h2_flag_padded, "PADDED"));
        _h2_frame_flags.insert(std::make_pair(h2_flag_t::h2_flag_priority, "PRIORITY"));
    }
    if (_h2_frame_flags2.empty()) {
        _h2_frame_flags2.insert(std::make_pair(h2_flag_t::h2_flag_ack, "ACK"));
    }
    if (_h2_frame_settings.empty()) {
        _h2_frame_settings.insert({h2_settings_header_table_size, "SETTINGS_HEADER_TABLE_SIZE"});
        _h2_frame_settings.insert({h2_settings_enable_push, "SETTINGS_ENABLE_PUSH"});
        _h2_frame_settings.insert({h2_settings_max_concurrent_streams, "SETTINGS_MAX_CONCURRENT_STREAMS"});
        _h2_frame_settings.insert({h2_settings_initial_window_size, "SETTINGS_INITIAL_WINDOW_SIZE"});
        _h2_frame_settings.insert({h2_settings_max_frame_size, "SETTINGS_MAX_FRAME_SIZE"});
        _h2_frame_settings.insert({h2_settings_max_header_list_size, "SETTINGS_MAX_HEADER_LIST_SIZE"});
    }
}

std::string http_resource::get_h2_frame_name(uint8 type) {
    std::string name;
    t_maphint<uint8, std::string> hint(_h2_frame_names);
    hint.find(type, &name);
    return name;
}

std::string http_resource::get_h2_frame_flag(uint8 flag) {
    std::string flag_name;
    t_maphint<uint8, std::string> hint(_h2_frame_flags);
    hint.find(flag, &flag_name);
    return flag_name;
}

void http_resource::for_each_h2_frame_flag_names(uint8 type, uint8 flags, std::function<void(uint8, const std::string&)> func) {
    if (flags && func) {
        switch (type) {
            case h2_frame_t::h2_frame_settings:
            case h2_frame_t::h2_frame_ping:
                for (auto item : _h2_frame_flags2) {
                    uint8 flag = item.first;
                    if (flags & flag) {
                        func(flag, item.second);
                    }
                }
                break;
            default:
                for (auto item : _h2_frame_flags) {
                    uint8 flag = item.first;
                    if (flags & flag) {
                        func(flag, item.second);
                    }
                }
                break;
        }
    }
}

std::string http_resource::get_h2_settings_name(uint16 type) {
    std::string name;
    t_maphint<uint16, std::string> hint(_h2_frame_settings);
    hint.find(type, &name);
    return name;
}

http_static_table_entry h2_static_entries[] = {
    {1, ":authority"},
    {2, ":method", "GET"},
    {3, ":method", "POST"},
    {4, ":path", "/"},
    {5, ":path", "/index.html"},
    {6, ":scheme", "http"},
    {7, ":scheme", "https"},
    {8, ":status", "200"},
    {9, ":status", "204"},
    {10, ":status", "206"},
    {11, ":status", "304"},
    {12, ":status", "400"},
    {13, ":status", "404"},
    {14, ":status", "500"},
    {15, "accept-charset"},
    {16, "accept-encoding", "gzip,deflate"},
    {17, "accept-language"},
    {18, "accept-ranges"},
    {19, "accept"},
    {20, "access-control-allow-origin"},
    {21, "age"},
    {22, "allow"},
    {23, "authorization"},
    {24, "cache-control"},
    {25, "content-disposition"},
    {26, "content-encoding"},
    {27, "content-language"},
    {28, "content-length"},
    {29, "content-location"},
    {30, "content-range"},
    {31, "content-type"},
    {32, "cookie"},
    {33, "date"},
    {34, "etag"},
    {35, "expect"},
    {36, "expires"},
    {37, "from"},
    {38, "host"},
    {39, "if-match"},
    {40, "if-modified-since"},
    {41, "if-none-match"},
    {42, "if-range"},
    {43, "if-unmodified-since"},
    {44, "last-modified"},
    {45, "link"},
    {46, "location"},
    {47, "max-forwards"},
    {48, "proxy-authenticate"},
    {49, "proxy-authorization"},
    {50, "range"},
    {51, "referer"},
    {52, "refresh"},
    {53, "retry-after"},
    {54, "server"},
    {55, "set-cookie"},
    {56, "strict-transport-security"},
    {57, "transfer-encoding"},
    {58, "user-agent"},
    {59, "vary"},
    {60, "via"},
    {61, "www-authenticate"},
};

void http_resource::for_each_hpack_static_table(std::function<void(uint32 index, const char* name, const char* value)> func) {
    /**
     * RFC 7541 HPACK: Header Compression for HTTP/2
     * Appendix A.  Static Table Definition
     */

    if (func) {
        for (size_t i = 0; i < RTL_NUMBER_OF(h2_static_entries); i++) {
            http_static_table_entry* item = h2_static_entries + i;
            func(item->index, item->name, item->value);
        }
    }
}

size_t http_resource::sizeof_hpack_static_table_entries() { return RTL_NUMBER_OF(h2_static_entries); }

}  // namespace net
}  // namespace hotplace
