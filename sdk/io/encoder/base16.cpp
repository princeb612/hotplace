/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.08.13   Soo Han, Kim        reboot base16
 */

#include <hotplace/sdk/io/encoder/base16.hpp>

namespace hotplace {
namespace io {

return_t base16_encode (const byte_t* source, size_t size, std::string& outpart)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        outpart.clear ();

        if (nullptr == source) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        char buf[3];
        size_t buflen = sizeof (buf);
        for (size_t cur = 0; cur < size; cur++) {
            byte_t item = source [cur];
            snprintf (buf, buflen, "%02x", item);
            outpart += buf[0];
            outpart += buf[1];
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t base16_encode (binary_t source, std::string& outpart)
{
    return base16_encode (&source[0], source.size (), outpart);
}

static byte_t conv (char c)
{
    byte_t ret = 0;
    if (('0' <= c) && (c <= '9')) {
        ret = c - '0'; // 0~9
    }
    if (('A' <= c) && (c <= 'F')) {
        ret = c - 'A' + 10; // 10~15
    }
    if (('a' <= c) && (c <= 'f')) {
        ret = c - 'a' + 10; // 10~15
    }
    return ret;
}

return_t base16_decode (const char* source, size_t size, binary_t& outpart)
{
    return_t ret = errorcode_t::success;

    outpart.clear ();

    for (size_t cur = 0; cur < size; cur += 2) {
        byte_t i = 0;
        i = conv (source[cur]) << 4;
        i += conv (source[cur + 1]);
        outpart.push_back (i);
    }

    return ret;
}

return_t base16_decode (std::string source, binary_t& outpart)
{
    return base16_decode (source.c_str (), source.size (), outpart);
}

}
}