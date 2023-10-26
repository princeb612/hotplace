/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/io/string/string.hpp>

namespace hotplace {
namespace io {

std::wstring A2W(const char* source, uint32 codepage) {
    std::wstring value;
    std::vector<wchar_t> buffer;

    if (source) {
        int sizeNeed = MultiByteToWideChar(codepage, 0, source, -1, nullptr, 0);
        if (sizeNeed > 0) {
            buffer.resize(sizeNeed);  // including null pad
            MultiByteToWideChar(codepage, 0, source, -1, &buffer[0], sizeNeed);
            value = &buffer[0];
        }
    }
    return value;
}

return_t A2W(std::wstring& target, const char* source, uint32 codepage) {
    return_t ret = errorcode_t::success;
    std::vector<wchar_t> buffer;

    target.clear();
    if (source) {
        int sizeNeed = MultiByteToWideChar(codepage, 0, source, -1, nullptr, 0);
        if (sizeNeed > 0) {
            buffer.resize(sizeNeed);  // including null pad
            MultiByteToWideChar(codepage, 0, source, -1, &buffer[0], sizeNeed);
            target = &buffer[0];
        }
    } else {
        ret = errorcode_t::invalid_parameter;
    }
    return ret;
}

}  // namespace io
}  // namespace hotplace
