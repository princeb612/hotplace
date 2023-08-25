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
    const char* text = "0123456789abcdefghijklmnopqrstuvwxyz!@#$%^&*()-_=+[{]}\\|;:'\",<.>/\?";
    std::string encoded;

    base16_encode ((byte_t*) text, strlen (text), encoded);
    binary_t decoded;
    base16_decode (encoded, decoded);
    printf ("%s\n", text);
    printf ("%s\n", encoded.c_str ());
    buffer_stream bs;
    dump_memory (&decoded[0], decoded.size (), &bs);
    printf ("%s\n", bs.c_str ());
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

    dump_memory ((byte_t*) source, source_size, &bs);
    printf ("input\n%s\n", bs.c_str ());
    dump_memory ((byte_t*) &encoded_b64[0], encoded_b64.size (), &bs);
    printf ("encoded\n%.*s\n", (int) bs.size (), bs.c_str ());
    dump_memory (&decoded_b64[0], decoded_b64.size (), &bs);
    printf ("decoded\n%.*s\n", (int) bs.size (), bs.c_str ());
}

void test_base64 ()
{
    _test_case.begin ("base64 encoding");
    const char* lyrics = "still a man hears what he wants to hear and disregards the rest";
    size_t len = strlen (lyrics);
    test_base64_routine (lyrics, len, base64_encoding_t::base64_encoding);
    test_base64_routine (lyrics, len, base64_encoding_t::base64url_encoding);
}

int main ()
{
    test_base16 ();
    test_base64 ();

    _test_case.report ();
    return _test_case.result ();
}
