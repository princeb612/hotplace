/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   wide2ansi.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/stream/tstring.hpp>

namespace hotplace {

return_t W2A(ansi_string& target, const wchar_t* source, uint32 codepage) { return W2A(&target, source, codepage); }

return_t W2A(stream_t* stream, const wchar_t* source, uint32 codepage) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream || nullptr == source) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::vector<char> buffer;
        int sizeNeed = WideCharToMultiByte(codepage, 0, source, -1, nullptr, 0, nullptr, nullptr);

        buffer.resize(sizeNeed);  // including null pad
        WideCharToMultiByte(codepage, 0, source, -1, buffer.data(), sizeNeed, nullptr, nullptr);
        if (sizeNeed >= sizeof(char)) {
            stream->write((void*)buffer.data(), (sizeNeed - 1) * sizeof(char));
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace hotplace
