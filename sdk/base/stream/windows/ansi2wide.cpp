/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   ansi2wide.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/stream/ansi_string.hpp>
#include <hotplace/sdk/base/stream/unicode/wide_string.hpp>

namespace hotplace {

return_t A2W(wide_string& target, const char* source, uint32 codepage) { return A2W(&target, source, codepage); }

return_t A2W(stream_t* stream, const char* source, uint32 codepage) {
    auto lambda = [](stream_t*& target, void* p, size_t len) -> void { target->write(p, len); };
    return ansi2wide(stream, lambda, source, codepage);
}

return_t A2W(std::wstring& target, const char* source, uint32 codepage) {
    auto lambda = [](std::wstring& target, void* p, size_t len) -> void { target.append(static_cast<wchar_t*>(p), len / sizeof(wchar_t)); };
    return ansi2wide(target, lambda, source, codepage);
};

}  // namespace hotplace
