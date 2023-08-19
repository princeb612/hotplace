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

void dump (bufferio_context_t* handle)
{
    bufferio bio;
    byte_t* data = nullptr;
    size_t size_data = 0;
    buffer_stream bs;

    bio.get (handle, &data, &size_data);
    dump_memory (data, size_data, &bs);
    printf ("dump\n%.*s\n", (unsigned) bs.size (), bs.c_str ());
}

void test_bufferio ()
{
    return_t ret = errorcode_t::success;
    bool test = true;
    size_t len = 0;
    size_t pos = 0;
    bufferio bio;
    bufferio_context_t* handle = nullptr;

    ret = bio.open (&handle, 8);
    _test_case.test (ret, __FUNCTION__, "open");

    ret = bio.printf (handle, "%s %d %1.1f", "sample", 1, 1.1);
    _test_case.test (ret, __FUNCTION__, "printf");
    dump (handle);

    _test_case.start ();
    ret = bio.replace (handle, "sample", "example", 0, 0);
    _test_case.test (ret, __FUNCTION__, "replace");
    dump (handle);

    _test_case.start ();
    ret = bio.cut (handle, 0, 8);
    _test_case.test (ret, __FUNCTION__, "cut");
    dump (handle);

    _test_case.start ();
    ret = bio.insert (handle, 0, "sample ", 7);
    _test_case.test (ret, __FUNCTION__, "insert");
    dump (handle);

    _test_case.start ();
    ret = bio.flush (handle);
    _test_case.test (ret, __FUNCTION__, "flush");
    dump (handle);

    // 0123456789a
    // hello world

    _test_case.start ();
    ret = bio.printf (handle, "hello world");
    _test_case.test (ret, __FUNCTION__, "printf");
    dump (handle);

    _test_case.start ();
    bio.size (handle, &len);
    _test_case.assert ((11 == len), __FUNCTION__, "size");
    dump (handle);

    _test_case.start ();
    pos = bio.find_first_of (handle, "world");
    _test_case.assert ((6 == pos), __FUNCTION__, format ("find_first_of -> %i", pos).c_str ());

    _test_case.start ();
    pos = bio.find_not_first_of (handle, "hello");
    _test_case.assert ((5 == pos), __FUNCTION__, format ("find_not_first_of -> %i", pos).c_str ());

    _test_case.start ();
    pos = bio.find_last_of (handle, "world");
    _test_case.assert ((6 == pos), __FUNCTION__, format ("find_last_of -> %i", pos).c_str ());

    _test_case.start ();
    pos = bio.find_not_last_of (handle, "world");
    _test_case.assert ((5 == pos), __FUNCTION__, format ("find_not_last_of -> %i", pos).c_str ());

    _test_case.start ();
    pos = bio.find_first_of (handle, isspace);
    _test_case.assert ((5 == pos), __FUNCTION__, format ("find_first_of -> %i", pos).c_str ());

    _test_case.start ();
    ret = bio.cut (handle, bio.find_first_of (handle, isspace), 1);
    _test_case.test (ret, __FUNCTION__, "cut");

    _test_case.start ();
    bio.size (handle, &len);
    _test_case.assert ((10 == len), __FUNCTION__, "size");
    dump (handle);

    std::string sample ("helloworld");

    _test_case.start ();
    test = bio.compare (handle, sample.c_str (), sample.size ());
    _test_case.assert ((true == test), __FUNCTION__, "compare");

    _test_case.start ();
    ret = bio.flush (handle);
    _test_case.test (ret, __FUNCTION__, "flush");

    _test_case.start ();
    ret = bio.printf (handle, "sample sample sample");
    _test_case.test (ret, __FUNCTION__, "printf");
    dump (handle);

    _test_case.start ();
    ret = bio.replace (handle, "sample", "example");
    _test_case.test (ret, __FUNCTION__, "replace");
    dump (handle);

    std::string sample2 ("example example example");

    _test_case.start ();
    test = bio.compare (handle, sample2.c_str (), sample2.size ());
    _test_case.assert ((true == test), __FUNCTION__, "compare");

    _test_case.start ();
    ret = bio.replace (handle, "example", "sample", 1, bufferio_flag_t::run_once);
    _test_case.test (ret, __FUNCTION__, "replace");
    dump (handle);

    std::string sample3 ("example sample example");

    _test_case.start ();
    test = bio.compare (handle, sample3.c_str (), sample3.size ());
    _test_case.assert ((true == test), __FUNCTION__, "compare");

    _test_case.start ();
    ret = bio.close (handle);
    _test_case.test (ret, __FUNCTION__, "close");
}

int main ()
{
    test_bufferio ();

    _test_case.report ();
    return _test_case.result ();
}
