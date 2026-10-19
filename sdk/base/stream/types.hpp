/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   types.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_STREAM_TYPES__
#define __HOTPLACE_SDK_BASE_STREAM_TYPES__

#include <hotplace/sdk/base/basic/types.hpp>
#include <list>

namespace hotplace {

struct bufferio_context_t;

class ansi_string;
class basic_stream;
class bufferio;
#if defined _WIN32 || defined _WIN64
class wide_string;
#endif

#if defined _WIN32 || defined _WIN64

template <typename T, typename WRITER>
return_t ansi2wide(T& target, WRITER&& writer, const char* source, uint32 codepage = 0) {
    return_t ret = errorcode_t::success;

    if (nullptr == source) {
        return errorcode_t::invalid_parameter;
    }

    std::vector<wchar_t> buffer;
    int sizeNeed = MultiByteToWideChar(codepage, 0, source, -1, nullptr, 0);
    if (sizeNeed > 0) {
        buffer.resize(sizeNeed);  // including null pad
        MultiByteToWideChar(codepage, 0, source, -1, buffer.data(), sizeNeed);
        if (size_t(sizeNeed) >= sizeof(wchar_t)) {
            writer(target, (void*)buffer.data(), (sizeNeed - 1) * sizeof(wchar_t));
        }
    }
    return ret;
};

template <typename T, typename WRITER>
return_t wide2ansi(T& target, WRITER&& writer, const wchar_t* source, uint32 codepage = 0) {
    return_t ret = errorcode_t::success;

    if (nullptr == source) {
        return errorcode_t::invalid_parameter;
    }

    std::vector<char> buffer;
    int sizeNeed = WideCharToMultiByte(codepage, 0, source, -1, nullptr, 0, nullptr, nullptr);

    buffer.resize(sizeNeed);  // including null pad
    WideCharToMultiByte(codepage, 0, source, -1, buffer.data(), sizeNeed, nullptr, nullptr);
    if (size_t(sizeNeed) >= sizeof(char)) {
        writer(target, (void*)buffer.data(), (sizeNeed - 1) * sizeof(char));
    }
    return ret;
}

return_t A2W(wide_string& target, const char* source, uint32 codepage = 0);
return_t W2A(ansi_string& target, const wchar_t* source, uint32 codepage = 0);
return_t A2W(stream_t* stream, const char* source, uint32 codepage = 0);
return_t W2A(stream_t* stream, const wchar_t* source, uint32 codepage = 0);
return_t A2W(std::wstring& target, const char* source, uint32 codepage = 0);
return_t W2A(std::string& target, const wchar_t* source, uint32 codepage = 0);

#endif

}  // namespace hotplace

#endif
