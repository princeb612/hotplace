/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/sdk.hpp>
#include <stdio.h>
#include <iostream>

using namespace hotplace;
using namespace hotplace::io;

test_case _test_case;

void test_base16 ()
{
    return_t ret = errorcode_t::success;
    constexpr char text[] = "0123456789abcdefghijklmnopqrstuvwxyz!@#$%^&*()-_=+[{]}\\|;:'\",<.>/\?";
    std::string encoded;

    base16_encode ((byte_t*) text, strlen (text), encoded);
    binary_t decoded;
    ret = base16_decode (encoded, decoded);

    {
        test_case_notimecheck notimecheck (_test_case);

        printf ("input : %s\n", text);
        printf ("encode: %s\n", encoded.c_str ());
        buffer_stream bs;
        dump_memory (&decoded[0], decoded.size (), &bs);
        printf ("dump decoded\n%s\n", bs.c_str ());
    }

    bool test = false;
    test = (strlen (text) == decoded.size ());
    _test_case.assert (test, __FUNCTION__, "base16");
}

void test_base16_func ()
{
    return_t ret = errorcode_t::success;
    constexpr byte_t text [] = "still a man hears what he wants to hear and disregards the rest";
    buffer_stream bs;

    /* return_t base16_encode (const byte_t* source, size_t size, char* buf, size_t* buflen) */
    size_t size = 0;
    std::vector<char> buf;

    base16_encode (text, RTL_NUMBER_OF (text), nullptr, &size);
    buf.resize (size);
    ret = base16_encode (text, RTL_NUMBER_OF (text), &buf[0], &size);
    dump_memory ((byte_t*) &buf[0], buf.size (), &bs);
    std::cout << bs.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "case1");

    /* return_t base16_encode (const byte_t* source, size_t size, std::string& outpart) */
    std::string strbuf;
    ret = base16_encode (text, RTL_NUMBER_OF (text), strbuf);
    dump_memory (strbuf, &bs);
    std::cout << bs.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "case2");

    /* return_t base16_encode (const byte_t* source, size_t size, stream_t* stream) */
    buffer_stream streambuf;
    ret = base16_encode (text, RTL_NUMBER_OF (text), &streambuf);
    dump_memory (streambuf.data (), streambuf.size (), &bs);
    std::cout << bs.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "case3");
}

void test_base16_decode ()
{
    return_t ret = errorcode_t::success;
    std::string encoded ("0x000102030405060708090a0b0c0d0e0f808182838485868788898a8b8c8d8e8f");

    binary_t decoded;

    ret = base16_decode (encoded, decoded);

    {
        test_case_notimecheck notimecheck (_test_case);

        buffer_stream bs;
        dump_memory (&decoded[0], decoded.size (), &bs);
        printf ("%s\n", bs.c_str ());
    }

    bool test = false;
    test = ((encoded.size () / 2) == decoded.size ());
    _test_case.test (ret, __FUNCTION__, "base16");
}

void test_base64_routine (const char* source, size_t source_size, int encoding)
{
    return_t ret = errorcode_t::success;
    buffer_stream bs;
    std::string encoded_b64;
    binary_t decoded_b64;

    _test_case.reset_time ();
    base64_encode ((byte_t*) source, source_size, encoded_b64, encoding);
    base64_decode (encoded_b64, decoded_b64, encoding);
    _test_case.assert (0 == memcmp (source, &decoded_b64[0], source_size), __FUNCTION__, "base64_decode");

    {
        test_case_notimecheck notimecheck (_test_case);

        dump_memory ((byte_t*) source, source_size, &bs);
        printf ("input\n%s\n", bs.c_str ());
        dump_memory ((byte_t*) &encoded_b64[0], encoded_b64.size (), &bs);
        printf ("encoded\n%.*s\n", (int) bs.size (), bs.c_str ());
        dump_memory (&decoded_b64[0], decoded_b64.size (), &bs);
        printf ("decoded\n%.*s\n", (int) bs.size (), bs.c_str ());
    }
}

void test_base64 ()
{
    constexpr char lyrics[] = "still a man hears what he wants to hear and disregards the rest";
    size_t len = strlen (lyrics);

    test_base64_routine (lyrics, len, base64_encoding_t::base64_encoding);
    test_base64_routine (lyrics, len, base64_encoding_t::base64url_encoding);
}

int main ()
{
    _test_case.begin ("base16 encoding");
    test_base16 ();
    test_base16_func ();
    test_base16_decode ();

    _test_case.begin ("base64 encoding");
    test_base64 ();

    _test_case.report (5);
    return _test_case.result ();
}
