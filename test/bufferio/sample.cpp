/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::io;

test_case _test_case;

void dump(bufferio_context_t* handle) {
    test_case_notimecheck notimecheck(_test_case);

    bufferio bio;
    byte_t* data = nullptr;
    size_t size_data = 0;
    basic_stream bs;

    bio.get(handle, &data, &size_data);
    dump_memory(data, size_data, &bs);
    printf("dump\n%.*s\n", (unsigned)bs.size(), bs.c_str());
}

void test_vprintf(bufferio_context_t* handle, const char* fmt, ...) {
    return_t ret = errorcode_t::success;
    bufferio io;
    va_list ap;

    va_start(ap, fmt);
    ret = io.vprintf(handle, fmt, ap);
    va_end(ap);

    _test_case.test(ret, __FUNCTION__, "vprintf");
}

void test_bufferio() {
    return_t ret = errorcode_t::success;
    bool test = true;
    size_t len = 0;
    size_t pos = 0;
    bufferio bio;
    bufferio_context_t* handle = nullptr;

    ret = bio.open(&handle, 8);
    _test_case.test(ret, __FUNCTION__, "open");

    ret = bio.printf(handle, "%s %d %1.1f", "sample", 1, 1.1);
    _test_case.test(ret, __FUNCTION__, "printf");
    dump(handle);

    test_vprintf(handle, "%s %f %i", "phi", 3.141592, 123);
    dump(handle);

    ret = bio.replace(handle, "sample", "example", 0, 0);
    _test_case.test(ret, __FUNCTION__, "replace");
    dump(handle);

    ret = bio.cut(handle, 0, 8);
    _test_case.test(ret, __FUNCTION__, "cut");
    dump(handle);

    ret = bio.insert(handle, 0, "sample ", 7);
    _test_case.test(ret, __FUNCTION__, "insert");
    dump(handle);

    size_t size = 0;
    ret = bio.size(handle, &size);
    _test_case.test(ret, __FUNCTION__, "size %zi", size);

    uint32 begin = 7;
    uint32 length = size - begin;
    ret = bio.cut(handle, begin, length);
    _test_case.test(ret, __FUNCTION__, "cut from %i len %i", begin, length);
    dump(handle);

    ret = bio.write(handle, "test", 4);
    _test_case.test(ret, __FUNCTION__, "write");
    dump(handle);

    ret = bio.clear(handle);
    _test_case.test(ret, __FUNCTION__, "clear");
    dump(handle);

    // 0123456789a
    // hello world

    ret = bio.printf(handle, "hello world");
    _test_case.test(ret, __FUNCTION__, "printf");
    dump(handle);

    bio.size(handle, &len);
    _test_case.assert((11 == len), __FUNCTION__, "size");
    dump(handle);

    pos = bio.find_first_of(handle, "world");
    _test_case.assert((6 == pos), __FUNCTION__, "find_first_of -> %i", pos);

    pos = bio.find_not_first_of(handle, "hello");
    _test_case.assert((5 == pos), __FUNCTION__, "find_not_first_of -> %i", pos);

    pos = bio.find_last_of(handle, "world");
    _test_case.assert((6 == pos), __FUNCTION__, "find_last_of -> %i", pos);

    pos = bio.find_not_last_of(handle, "world");
    _test_case.assert((5 == pos), __FUNCTION__, "find_not_last_of -> %i", pos);

    pos = bio.find_first_of(handle, isspace);
    _test_case.assert((5 == pos), __FUNCTION__, "find_first_of -> %i", pos);

    ret = bio.cut(handle, bio.find_first_of(handle, isspace), 1);
    _test_case.test(ret, __FUNCTION__, "cut");

    bio.size(handle, &len);
    _test_case.assert((10 == len), __FUNCTION__, "size");
    dump(handle);

    std::string sample("helloworld");

    test = bio.compare(handle, sample.c_str(), sample.size());
    _test_case.assert((true == test), __FUNCTION__, "compare");

    bio.printf(handle, "\n ");
    pos = bio.find_not_last_of(handle, isspace);
    printf("find_not_last_of %zi\n", pos);
    _test_case.assert((10 == pos), __FUNCTION__, "find_not_last_of -> %i", pos);

    ret = bio.clear(handle);
    _test_case.test(ret, __FUNCTION__, "clear");

    ret = bio.printf(handle, "sample sample sample");
    _test_case.test(ret, __FUNCTION__, "printf");
    dump(handle);

    ret = bio.replace(handle, "sample", "example");
    _test_case.test(ret, __FUNCTION__, "replace");
    dump(handle);

    std::string sample2("example example example");

    test = bio.compare(handle, sample2.c_str(), sample2.size());
    _test_case.assert((true == test), __FUNCTION__, "compare");

    ret = bio.replace(handle, "example", "sample", 1, bufferio_flag_t::run_once);
    _test_case.test(ret, __FUNCTION__, "replace");
    dump(handle);

    std::string sample3("example sample example");

    test = bio.compare(handle, sample3.c_str(), sample3.size());
    _test_case.assert((true == test), __FUNCTION__, "compare");

    ret = bio.close(handle);
    _test_case.test(ret, __FUNCTION__, "close");
}

void test_bufferio2() {
    _test_case.begin("cases null-padded");
    // avoid c_str () return nullptr
    // std::cout << nullptr
    // printf ("%s", nullptr);
    bufferio bio;
    bufferio_context_t* handle = nullptr;
    byte_t* data = nullptr;
    size_t size_data = 0;

    bio.open(&handle, 8, 1);
    bio.get(handle, &data, &size_data);
    _test_case.assert(nullptr != data, __FUNCTION__, "c_str () after constructor");
    bio.printf(handle, "hello world");
    bio.clear(handle);
    bio.get(handle, &data, &size_data);
    _test_case.assert(nullptr != data, __FUNCTION__, "c_str () after clear");
    bio.close(handle);
}

int main() {
    test_bufferio();
    test_bufferio2();

    _test_case.report(5);
    return _test_case.result();
}
