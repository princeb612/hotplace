/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/io/stream/stream.hpp>

namespace hotplace {
namespace io {

return_t W2A (stream_interface* stream, const wchar_t* source, uint32 codepage)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (source) {
            std::vector <char> buffer;
            int sizeNeed = WideCharToMultiByte (codepage, 0, source, -1, nullptr, 0, nullptr, nullptr);

            buffer.resize (sizeNeed); // including null pad
            WideCharToMultiByte (codepage, 0, source, -1, &buffer[0], sizeNeed, nullptr, nullptr);
            if (sizeNeed >= (int) sizeof (wchar_t)) {
                stream->write ((void*) &buffer[0], sizeNeed - sizeof (char));
            }
        } else {
            ret = errorcode_t::invalid_parameter;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

}
}
