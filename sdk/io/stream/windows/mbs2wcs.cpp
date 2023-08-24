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
//#include <hotplace/sdk/io/string/string.hpp>

namespace hotplace {
namespace io {

return_t A2W (stream_t* stream, const char* source, uint32 codepage)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::vector <wchar_t> buffer;
        if (source) {
            int sizeNeed = MultiByteToWideChar (codepage, 0, source, -1, nullptr, 0);
            if (sizeNeed > 0) {
                buffer.resize (sizeNeed); // including null pad
                MultiByteToWideChar (codepage, 0, source, -1, &buffer[0], sizeNeed);
                if (sizeNeed >= (int) sizeof (char)) {
                    stream->write ((void*) &buffer[0], sizeNeed - sizeof (wchar_t));
                }
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
