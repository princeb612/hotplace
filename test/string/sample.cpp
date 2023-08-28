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

void test_format ()
{
    _test_case.begin ("format");
    _test_case.reset_time ();
    std::string text = format ("%s %d %1.1f\n", "sample", 1, 1.1f);
    std::cout << text.c_str () << std::endl;
    _test_case.assert (true, __FUNCTION__, "format");
}

void test_getline ()
{
    _test_case.begin ("getline");

    return_t ret = errorcode_t::success;
    const char* stream_data = " line1 \nline2 \n  line3\nline4";
    size_t stream_size = strlen (stream_data);
    size_t pos = 0;
    size_t brk = 0;

    _test_case.reset_time ();

    for (;;) {
        ret = getline (stream_data, stream_size, pos, &brk);
        if (errorcode_t::success != ret) {
            break;
        }

        // line contains CR and NL
        //printf ("%.*s\n", brk - pos, stream_data + pos);
        std::string line (stream_data + pos, brk - pos);
        ltrim (rtrim (line));
        printf ("%s\n", line.c_str ());

        pos = brk;
    }

    _test_case.assert (true, __FUNCTION__, "getline");
}

void test_gettoken ()
{
    _test_case.begin ("gettoken");

    std::string token = "=|", value;
    std::string data = "key=item1|value1|link1";

    _test_case.reset_time ();

    gettoken (data, token, 0, value);  // "key"
    _test_case.assert (value == "key", __FUNCTION__, "gettoken");

    gettoken (data, token, 1, value);  // "item1"
    _test_case.assert (value == "item1", __FUNCTION__, "gettoken");

    gettoken (data, token, 2, value);  // "value1"
    _test_case.assert (value == "value1", __FUNCTION__, "gettoken");

    gettoken (data, token, 3, value);  // "link1"
    _test_case.assert (value == "link1", __FUNCTION__, "gettoken");
}

void test_hexbin ()
{
    _test_case.begin ("base16");
    _test_case.reset_time ();

    const char* message = "sample";
    const byte_t* inpart = (const byte_t*) message;

    std::string hex;
    base16_encode (inpart, 5, hex);
    std::cout << hex.c_str () << std::endl;

    binary_t bin;
    base16_decode (hex, bin);
    buffer_stream bs;
    dump_memory (&bin[0], bin.size (), &bs);
    printf ("%s\n", bs.c_str ());

    _test_case.assert (true, __FUNCTION__, "base16");
}

void test_obfuscate_string ()
{
    _test_case.begin ("obfuscate_string");

    bool test = false;
    buffer_stream bs;
    binary_t bin;
    std::string str;
    char helloworld [] = { 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', 0 };

    _test_case.reset_time ();

    obfuscate_string obf (helloworld);
    bin << obf;

    {
        test_case_notimecheck notimecheck (_test_case);
        dump_memory (bin, &bs);
        std::cout << bs.c_str () << std::endl;
    }

    _test_case.assert ((0 == memcmp (helloworld, &bin[0], bin.size ())), __FUNCTION__, "binary_t << obfuscate");

    str << obf;

    {
        test_case_notimecheck notimecheck (_test_case);
        dump_memory (str, &bs);
        std::cout << bs.c_str () << std::endl;
    }

    _test_case.assert ((0 == memcmp (helloworld, str.c_str (), str.size ())), __FUNCTION__, "std::string << obfuscate");

    obfuscate_string obf2 (helloworld);

    _test_case.assert (obf == obf2, __FUNCTION__, "assign and operator ==");

    obf << helloworld;
    obf2 << helloworld;

    {
        test_case_notimecheck notimecheck (_test_case);

        bin.clear ();
        bin << obf;
        dump_memory (bin, &bs);
        std::cout << bs.c_str () << std::endl;
    }
    _test_case.assert (obf == obf2, __FUNCTION__, "append and operator ==");
}

typedef struct {
    std::string str;
} myprintf_context_t;

int callback_printf (void* context, const char* buf, int len)
{
    myprintf_context_t* handle = (myprintf_context_t*) context;

    handle->str.append (buf, len);
    return 0;
}

void test_printf ()
{
    _test_case.begin ("printf");
    _test_case.reset_time ();

    myprintf_context_t context;
    printf_runtime (&context, &callback_printf, "%s %i %1.1f", "sample", 1, 1.1);
    std::cout << context.str.c_str () << std::endl;

    _test_case.assert (true, __FUNCTION__, "printf");
}

void test_replace ()
{
    _test_case.begin ("replace");
    _test_case.reset_time ();

    std::string data ("hello world");
    replace (data, "world", "neighbor");
    std::cout << data.c_str () << std::endl;

    _test_case.assert (true, __FUNCTION__, "replace");
}

void test_scan ()
{
    _test_case.begin ("scan");
    _test_case.reset_time ();

    return_t ret = errorcode_t::success;
    const char* data = "hello world\n ";
    size_t pos = 0;
    size_t brk = 0;
    while (true) {
        ret = scan (data, strlen (data), pos, &brk, isspace);
        if (errorcode_t::success != ret) {
            break;
        }
        printf ("position isspace %zi\n", brk);
        pos = brk;
    }
    _test_case.assert (true, __FUNCTION__, "scan");

    buffer_stream bs;
    dump_memory ((byte_t*) data, strlen (data), &bs, 16, 0, 0x0, dump_memory_flag_t::header);
    std::cout << bs.c_str () << std::endl;
}

void test_scan2 ()
{
    _test_case.begin ("scan");
    _test_case.reset_time ();

    return_t ret = errorcode_t::success;
    const char* data = "hello world\n wide world\n";
    const char* match = "world";
    size_t pos = 0;
    size_t brk = 0;
    while (true) {
        ret = scan (data, strlen (data), pos, &brk, match);
        if (errorcode_t::success != ret) {
            break;
        }
        printf ("position %zi\n", brk);
        pos = brk + strlen (match);
    }
    _test_case.assert (true, __FUNCTION__, "scan");

    buffer_stream bs;
    dump_memory ((byte_t*) data, strlen (data), &bs, 16, 0, 0x0, dump_memory_flag_t::header);
    std::cout << bs.c_str () << std::endl;
}

void test_split ()
{
    _test_case.begin ("split");
    _test_case.reset_time ();

    split_context_t* handle = nullptr;
    size_t count = 0;
    split_begin (&handle, "test1.hello2.bye3..", ".");
    split_count (handle, count);
    binary_t data;
    for (size_t i = 0; i < count; i++) {
        split_get (handle, i, data);
        printf ("[%zi] (%zi) %.*s\n", i, data.size (), (unsigned) data.size (), &data [0]);
    }
    split_end (handle);

    _test_case.assert (true, __FUNCTION__, "split");
}

void test_string ()
{
    _test_case.begin ("ansi_string");
    _test_case.reset_time ();

    ansi_string astr;
    astr << "sample "
#if defined _WIN32 || defined _WIN64
        << L"unicode "
#endif
        << (uint16) 1 << " " << 1.1f;
    std::cout << astr.c_str () << std::endl;

    _test_case.assert (true, __FUNCTION__, "ansi_string");
}

void test_tokenize ()
{
    _test_case.begin ("tokenize");
    _test_case.reset_time ();

    std::string data = "key=item1|value1|link1";
    size_t pos = 0;
    std::string token;
    for (;;) {
        token = tokenize (data, std::string ("=|"), pos);
        printf ("%s\n", token.c_str ());
        if ((size_t) -1 == pos) {
            break;
        }
    }

    _test_case.assert (true, __FUNCTION__, "tokenize");
}

int main ()
{
    test_format ();
    test_getline ();
    test_gettoken ();
    test_hexbin ();
    test_obfuscate_string ();
    test_printf ();
    test_replace ();
    test_scan ();
    test_scan2 ();
    test_split ();
    test_string ();
    test_tokenize ();

    _test_case.report (5);
    return _test_case.result ();
}
