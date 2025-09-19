/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>

namespace hotplace {
namespace crypto {

return_t get_opensslerror(int rc) {
    return_t ret = errorcode_t::success;
    if (rc < 0) {
        ret = errorcode_t::error_openssl_inside;
        uint32 option = get_trace_option();
        if (trace_option_t::trace_bt & option) {
            basic_stream stream;
            debug_trace_openssl(&stream);
            std::cout << stream;
        }
    }
    return ret;
}

return_t trace_openssl(return_t errorcode) {
    return_t ret = errorcode_t::success;

    if (errorcode_t::success != errorcode) {
        uint32 option = get_trace_option();
        if (trace_option_t::trace_bt & option) {
            basic_stream stream;
            debug_trace_openssl(&stream);
            std::cout << stream;
        }
    }
    return ret;
}

return_t debug_trace_openssl(stream_t *stream) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        unsigned long l = 0;
        char buf[256];

        std::string bio;
        const char *file = nullptr;
        const char *data = nullptr;
        int line = 0;
        int flags = 0;

        constexpr char constexpr_debugline[] = "[%s @ %d] %s\n";

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
        while (0 != (l = ERR_get_error_all(&file, &line, nullptr, &data, &flags))) {
#else
        while (0 != (l = ERR_get_error_line_data(&file, &line, &data, &flags))) {
#endif
            ERR_error_string_n(l, buf, sizeof(buf));
            stream->printf(constexpr_debugline, file, line, buf);
        }

        ERR_clear_error();
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
