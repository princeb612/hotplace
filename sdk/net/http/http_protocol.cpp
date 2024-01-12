/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/basic/sdk.hpp>
#include <sdk/net/http/http_protocol.hpp>
#include <sdk/net/tls/tls.hpp>

namespace hotplace {
namespace net {

http_protocol::http_protocol() : network_protocol() {
    // do nothing
}

http_protocol::~http_protocol() {
    // do nothing
}

return_t http_protocol::is_kind_of(void* stream, size_t stream_size) {
    return_t ret = errorcode_t::success;
    bool found = false;

    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (stream_size < 14) { /* at least need 'GET / HTTP/1.1' */
            ret = errorcode_t::more_data;
            __leave2;
        }

        struct _HTTP_TOKEN {
            size_t length;
            const char* method;
        };
        struct _HTTP_TOKEN _http_token[] = {
            {4, "HTTP"}, {3, "GET"}, {4, "POST"}, {3, "PUT"}, {6, "DELETE"}, {4, "HEAD"}, {7, "OPTIONS"}, {5, "TRACE"},
        };

        for (int i = 0; i < (int)RTL_NUMBER_OF(_http_token); i++) {
            if (stream_size >= _http_token[i].length) {
                int ret_compare = strnicmp((char*)stream, _http_token[i].method, _http_token[i].length);
                if (0 == ret_compare) {
                    found = true;
                    break;
                }
            }
        }

        if (false == found) {
            ret = errorcode_t::mismatch;
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t http_protocol::read_stream(basic_stream* stream, size_t* request_size, protocol_state_t* state) {
    const char* stream_data = (const char*)stream->data();
    uint32 stream_size = stream->size();

#if 0
    /* TEST */
    if (sizeMem > BUFSIZE1M) {
        *state = protocol_state_t::protocol_state_crash;
    }
#endif

    const char* search_stream_data = stream_data;
    /* "Content-Length: " */
    char STRING_CONTENT_LENGTH__[] = {
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', 0,
    };
    const char* search_content_length = strstr(stream_data, STRING_CONTENT_LENGTH__);
    if (search_content_length) {
        const char* end_of_content_length = search_content_length + strlen(STRING_CONTENT_LENGTH__);
        const char* search_carragereturn_newline = strstr(search_content_length, "\r\n\r\n");
        if (search_carragereturn_newline) {
            std::string content_length(end_of_content_length, search_carragereturn_newline - end_of_content_length);
            int ret_atoi = atoi(content_length.c_str());

            size_t size_need = (search_carragereturn_newline - stream_data) + 4 + ret_atoi;

            if (size_need > stream_size) {
                *state = protocol_state_t::protocol_state_data;
            } else {
                *request_size = size_need;
                *state = protocol_state_t::protocol_state_complete;
            }
        }
    } else {
        *state = protocol_state_t::protocol_state_data;

        const char* search_carragereturn_newline = strstr(search_stream_data, "\r\n\r\n");
        if (search_carragereturn_newline) {
            *request_size = (search_carragereturn_newline - stream_data + 4);
            *state = protocol_state_t::protocol_state_complete;
        }
    }

    return errorcode_t::success;
}

uint32 http_protocol::protocol_id() { return 80; }

}  // namespace net
}  // namespace hotplace
