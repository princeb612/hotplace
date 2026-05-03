/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_filestream.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <hotplace/testcase/io/sample.hpp>

void test_filestream() {
    _test_case.begin("filestream");
    file_stream fs;
    return_t ret = success;
    __try2 {
        const char* filename = "testfile";
        size_t filesize = 1024;

        ret = fs.open(filename, open_write);
        _test_case.test(ret, __FUNCTION__, "open");
        if (success != ret) {
            __leave2;
        }

        fs.truncate(filesize);
        _test_case.assert(fs.size() == filesize, __FUNCTION__, "truncate");

        ret = fs.begin_mmap();
        _test_case.test(ret, __FUNCTION__, "mmap");
        if (success != ret) {
            __leave2;
        }

        byte_t* ptr = fs.data();
        size_t size = fs.size();

        size_t i = 0;
        for (i = 0; i < size; i += 4) {
            *(uint32*)(ptr + i) = 0x12345678;
        }
        for (; i < size; ++i) {
            *(ptr + i) = (byte_t)(i % 16);
        }

        fs.end_mmap();

        fs.seek(0, FILE_BEGIN);
        uint32 value = 0;
        size_t size_read = 0;
        fs.read(&value, 4, &size_read);

        _test_case.assert(value == 0x12345678, __FUNCTION__, "read");

        unlink(filename);
    }
    __finally2 {}
}

void testcase_filestream() { test_filestream(); }
