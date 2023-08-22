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

void test_consolecolor ()
{
    _test_case.begin ("console_color");
    console_color col;

    _test_case.start ();
    console_style_t styles [] = { console_style_t::normal, console_style_t::bold, console_style_t::dim, console_style_t::italic, console_style_t::underline, console_style_t::invert, };
    console_color_t fgcolors [] = { console_color_t::black, console_color_t::red, console_color_t::green, console_color_t::yellow, console_color_t::blue, console_color_t::magenta, console_color_t::cyan, console_color_t::white, };
    console_color_t bgcolors [] = { console_color_t::black, console_color_t::white, };
    uint32 loop = 0;
    for (auto bgcolor : bgcolors) {
        col.set_bgcolor (bgcolor);
        for (auto style : styles) {
            col.set_style (style);
            for (auto fgcolor : fgcolors) {
                col.set_fgcolor (fgcolor);

                if (fgcolor != bgcolor) {
                    std::cout << col.turnon () << "test" << col.turnoff ();
                    if (15 == (loop % 16)) {
                        std::cout << std::endl;
                    }
                    ++loop;
                }
            }
        }
    }
    std::cout << std::endl;
    _test_case.assert (true, __FUNCTION__, format ("console color.1 loop %i times", loop).c_str ());

    col.set_style (console_style_t::normal);
    col.set_fgcolor (console_color_t::yellow);
    col.set_bgcolor (console_color_t::black);

    std::cout << col.turnon () << "color" << col.turnoff () << "default" << std::endl;
    _test_case.assert (true, __FUNCTION__, "console color.2");

    std::cout   << col.set_style (console_style_t::bold)
        .set_fgcolor (console_color_t::yellow)
        .set_bgcolor (console_color_t::black)
        .turnon ()
                << "color" << col.turnoff () << "default" << std::endl;

    _test_case.assert (true, __FUNCTION__, "console color.3");
}

void test_dumpmemory ()
{
    _test_case.begin ("dump_memory");
    return_t ret = errorcode_t::success;
    ansi_string bs;
    const char* text = "still a man hears what he wants to hear and disregards the rest"; // the boxer - Simon & Garfunkel

    ret = dump_memory ((byte_t*) text, strlen (text), &bs);
    std::cout << "dump " << std::endl << bs.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "dump const char*");

    std::string str (text);
    ret = dump_memory (str, &bs);
    std::cout << "dump " << std::endl << bs.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "dump std::string");

    binary_t bin = convert (str);
    ret = dump_memory (bin, &bs);
    std::cout << "dump " << std::endl << bs.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "dump std::vector<byte_t>");

    binary_t bin2;
    ret = dump_memory (bin2, &bs);
    std::cout << "dump " << std::endl << bs.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "dump blank");
}

void test_sprintf ()
{
    _test_case.begin ("sprintf");

    buffer_stream bs;
    valist va;

    va << 1 << "test string";                               // argc 2

    sprintf (&bs, "value1={1} value2={2}", va);             // value1=1 value2=test string
    sprintf (&bs, "value1={2} value2={1}", va);             // value1=test string value2=1
    sprintf (&bs, "value1={2} value2={1} value3={3}", va);  // value1=test string value2=1 value3={3}

    _test_case.assert (true, __FUNCTION__, "sprintf");
}

void test_stream ()
{
    _test_case.begin ("stream");

    buffer_stream bs;
    valist va;

    va << 1 << "test string";                   // argc 2

    sprintf (&bs, "value1={1} value2={2}", va); // value1=1 value2=test string
    std::cout << bs.c_str () << std::endl;
    bs.flush ();

    sprintf (&bs, "value1={2} value2={1}", va); // value1=test string value2=1
    std::cout << bs.c_str () << std::endl;
    bs.flush ();

    sprintf (&bs, "value1={2} value2={1} value3={3}", va); // value1=test string value2=1 value3={3}
    std::cout << bs.c_str () << std::endl;

    _test_case.assert (true, __FUNCTION__, "stream");
}

void test_stream_getline ()
{
    _test_case.begin ("stream::getline");

    return_t ret = errorcode_t::success;
    ansi_string stream (" line1 \nline2 \n  line3\nline4");
    ansi_string line;

    size_t pos = 0;
    size_t brk = 0;

    _test_case.start ();
    while (1) {
        ret = stream.getline (pos, &brk, line);
        if (errorcode_t::success != ret) {
            break;
        }
        line.rtrim ();
        printf ("%.*s\n", (unsigned) line.size (), line.c_str ());

        pos = brk;
    }
    _test_case.assert (true, __FUNCTION__, "getline");
}

void test_vtprintf ()
{
    _test_case.begin ("tokenize");

    buffer_stream bs;
    variant_t v;

    variant_set_int32 (v, 10);
    vtprintf (&bs, v);

    variant_set_str_new (v, "sample");
    vtprintf (&bs, v);
    variant_free (v);

    std::cout << bs.c_str () << std::endl;

    _test_case.assert (true, __FUNCTION__, "vtprintf");
}

int main ()
{
    test_consolecolor ();
    test_dumpmemory ();
    test_sprintf ();
    test_stream ();
    test_stream_getline ();
    test_vtprintf ();

    _test_case.report ();
    return _test_case.result ();
}
