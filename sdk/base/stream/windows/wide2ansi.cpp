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

return_t W2A(ansi_string& target, const wchar_t* source, uint32 codepage) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == source) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::vector<char> buffer;
        int sizeNeed = WideCharToMultiByte(codepage, 0, source, -1, nullptr, 0, nullptr, nullptr);

        buffer.resize(sizeNeed);  // including null pad
        WideCharToMultiByte(codepage, 0, source, -1, &buffer[0], sizeNeed, nullptr, nullptr);
        target = &buffer[0];
    }
    __finally2 {}
    return ret;
}

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
            MultiByteToWideChar(codepage, 0, source, -1, &buffer[0], sizeNeed);
            if (sizeNeed >= (int)sizeof(char)) {
                stream->write((void*)&buffer[0], sizeNeed - sizeof(wchar_t));
            }
        }
    }
    __finally2 {}
    return ret;
}

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
        WideCharToMultiByte(codepage, 0, source, -1, &buffer[0], sizeNeed, nullptr, nullptr);
        if (sizeNeed >= (int)sizeof(wchar_t)) {
            stream->write((void*)&buffer[0], sizeNeed - sizeof(char));
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace hotplace
