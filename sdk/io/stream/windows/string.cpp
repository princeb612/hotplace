/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/io/stream/string.hpp>

namespace hotplace {
namespace io {

return_t W2A (ansi_string& target, const wchar_t* source, uint32 codepage)
{
    return_t ret = errorcode_t::success;
    std::vector <char> buffer;

    if (source) {
        int sizeNeed = WideCharToMultiByte (codepage, 0, source, -1, nullptr, 0, nullptr, nullptr);

        buffer.resize (sizeNeed); // including null pad
        WideCharToMultiByte (codepage, 0, source, -1, &buffer[0], sizeNeed, nullptr, nullptr);
        target = &buffer[0];
    } else {
        ret = errorcode_t::invalid_parameter;
    }
    return ret;
}

}
}  // namespace
