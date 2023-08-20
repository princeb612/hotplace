/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.08.13   Soo Han, Kim        reboot hex2bin
 */

#include <hotplace/sdk/io/string/string.hpp>

namespace hotplace {
namespace io {

hex2bin::hex2bin () : _flags (0)
{
    // do nothing
}

hex2bin& hex2bin::set_flags (uint32 flags)
{
    _flags = flags;
    return *this;
}

uint32 hex2bin::get_flags ()
{
    return _flags;
}

return_t hex2bin::convert (binary_t inpart, std::string& outpart)
{
    if (_flags & hex2bin_flag_t::refresh) {
        outpart.clear ();
    }
    return convert (&inpart[0], inpart.size (), outpart);
}

return_t hex2bin::convert (const byte_t* source, size_t size, std::string& outpart)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (_flags & hex2bin_flag_t::refresh) {
            outpart.clear ();
        }

        if (nullptr == source) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        bool is_be = is_big_endian ();
        uint32 flags = get_flags ();
        if (flags & hex2bin_flag_t::prefix_0x) {
            outpart += "0x";
        }
        bool uppercase = (flags & hex2bin_flag_t::uppercase) ? true : false;
        char buf[3];
        size_t buflen = sizeof (buf);
        for (size_t cur = 0; cur < size; cur++) {
            byte_t item = source [cur];
            snprintf (buf, buflen, "%02x", item);
            if (is_be) {
                outpart += buf[1];
                outpart += buf[0];
            } else {
                outpart += buf[0];
                outpart += buf[1];
            }
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t hex2bin::convert (std::string inpart, binary_t& outpart)
{
    return convert (inpart.c_str (), inpart.size (), outpart);
}

return_t hex2bin::convert (const char* source, size_t size, binary_t& outpart)
{
    return_t ret = errorcode_t::success;
    bool is_be = is_big_endian ();

    if (_flags & hex2bin_flag_t::refresh) {
        outpart.clear ();
    }

    for (size_t cur = 0; cur < size; cur += 2) {
        byte_t i = 0;
        if (is_be) {
            i = c2i (source[cur]);
            i += c2i (source[cur + 1]) << 4;
        } else {
            i = c2i (source[cur]) << 4;
            i += c2i (source[cur + 1]);
        }
        outpart.insert (outpart.end (), i);
    }

    return ret;
}

std::string hex2bin::convert (binary_t bin)
{
    std::string outpart;

    bool is_be = is_big_endian ();
    char buf[3];
    size_t buflen = sizeof (buf);

    for (size_t cur = 0; cur < bin.size (); cur++) {
        byte_t item = bin[cur];
        snprintf (buf, buflen, "%02x", item);
        if (is_be) {
            outpart += buf[1];
            outpart += buf[0];
        } else {
            outpart += buf[0];
            outpart += buf[1];
        }
    }

    return outpart;
}

binary_t hex2bin::convert (std::string hex)
{
    binary_t outpart;
    bool is_be = is_big_endian ();

    for (size_t cur = 0; cur < hex.size (); cur += 2) {
        byte_t i = 0;
        if (is_be) {
            i = c2i (hex[cur]);
            i += c2i (hex[cur + 1]) << 4;
        } else {
            i = c2i (hex[cur]) << 4;
            i += c2i (hex[cur + 1]);
        }
        outpart.insert (outpart.end (), i);
    }
    return outpart;
}

int hex2bin::c2i (char c)
{
    int ret = 0;

    if (('0' <= c) && (c <= '9')) {
        ret = c - '0';                                  /* '0' 0x30 ~ '9' 0x39 */
    }
    if (('A' <= c) && (c <= 'F')) {
        ret = c - 'A' + 10;                             /* 'A' 0x41 ~ 'F' 0x46 */
    }
    if (('a' <= c) && (c <= 'f')) {
        ret = c - 'a' + 10;                             /* 'a' 0x61 ~ 'f' 0x66 */
    }
    return ret;
}

}
}
