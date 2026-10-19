/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   wide2ansi.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/stream/ansi_string.hpp>

namespace hotplace {

return_t W2A(ansi_string& target, const wchar_t* source, uint32 codepage) { return W2A(&target, source, codepage); }

return_t W2A(stream_t* stream, const wchar_t* source, uint32 codepage) {
    auto lambda = [](stream_t*& target, void* p, size_t len) -> void { target->write(p, len); };
    return wide2ansi(stream, lambda, source, codepage);
}

return_t W2A(std::string& target, const wchar_t* source, uint32 codepage) {
    auto lambda = [](std::string& target, void* p, size_t len) -> void { target.append(static_cast<char*>(p), len); };
    return wide2ansi(target, lambda, source, codepage);
};

}  // namespace hotplace
