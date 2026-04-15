/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/stream/tstring.hpp>

namespace hotplace {

return_t A2W(wide_string& target, const char* source, uint32 codepage) { return A2W(&target, source, codepage); }

return_t A2W(stream_t* stream, const char* source, uint32 codepage) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream || nullptr == source) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::vector<wchar_t> buffer;
        int sizeNeed = MultiByteToWideChar(codepage, 0, source, -1, nullptr, 0);
        if (sizeNeed > 0) {
            buffer.resize(sizeNeed);  // including null pad
            MultiByteToWideChar(codepage, 0, source, -1, buffer.data(), sizeNeed);
            if (sizeNeed >= sizeof(wchar_t)) {
                stream->write((void*)buffer.data(), (sizeNeed - 1) * sizeof(wchar_t));
            }
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace hotplace
