/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.08.13   Soo Han, Kim        reboot : bin2hex, hex2bin
 */

#include <hotplace/sdk/base/basic/base16.hpp>

namespace hotplace {

return_t base16_encode (const byte_t* source, size_t size, char* buf, size_t* buflen)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == source || nullptr == buflen) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t size_buf = *buflen;
        size_t size_necessary = (size << 1) + 1;

        *buflen = size_necessary;

        if (size_buf < size_necessary) {
            ret = errorcode_t::insufficient_buffer;
            __leave2;
        }

        if (nullptr == buf) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const byte_t* p = source;
        char* target = buf;
        size_t cur = 0;
        for (; cur < size; p++, target += 2, cur++) {
            snprintf (target, 3, "%02x", *p);
        }
        *target = 0;
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

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

return_t base16_encode (const byte_t* source, size_t size, stream_t* stream)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == source || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        stream->clear ();

        for (size_t cur = 0; cur < size; cur++) {
            byte_t item = source [cur];
            stream->printf ("%02x", item);
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t base16_encode (binary_t const& source, char* buf, size_t* buflen)
{
    return base16_encode (&source[0], source.size (), buf, buflen);
}

return_t base16_encode (binary_t const& source, std::string& outpart)
{
    return base16_encode (&source[0], source.size (), outpart);
}

std::string base16_encode (binary_t const& source)
{
    std::string outpart;

    base16_encode (source, outpart);
    return outpart;
}

return_t base16_encode (binary_t const& source, stream_t* stream)
{
    return base16_encode (&source[0], source.size (), stream);
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

    __try2
    {
        if (nullptr == source) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        outpart.clear ();

        if (size % 2) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        size_t cur = 0;
        if ((size > 2) && (0 == strnicmp (source, "0x", 2))) {
            cur = 2;
        }

        for (; cur < size; cur += 2) {
            byte_t i = 0;
            i = conv (source[cur]) << 4;
            i += conv (source[cur + 1]);
            outpart.push_back (i);
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t base16_decode (const char* source, size_t size, stream_t* stream)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == source || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        stream->clear ();

        if (size % 2) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        size_t cur = 0;
        if ((size > 2) && (0 == strnicmp (source, "0x", 2))) {
            cur = 2;
        }

        for (; cur < size; cur += 2) {
            byte_t i = 0;
            i = conv (source[cur]) << 4;
            i += conv (source[cur + 1]);
            stream->write (&i, 1);
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t base16_decode (std::string const& source, binary_t& outpart)
{
    return base16_decode (source.c_str (), source.size (), outpart);
}

return_t base16_decode (std::string const& source, stream_t* stream)
{
    return base16_decode (source.c_str (), source.size (), stream);
}

binary_t base16_decode (const char* source)
{
    return base16_decode (source, strlen (source));
}

binary_t base16_decode (const char* source, size_t size)
{
    binary_t outpart;

    base16_decode (source, size, outpart);
    return outpart;
}

binary_t base16_decode (std::string const& source)
{
    binary_t outpart;

    base16_decode (source, outpart);
    return outpart;
}

}
