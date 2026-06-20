/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   printf.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_STREAM_SPRINTF__
#define __HOTPLACE_SDK_BASE_STREAM_SPRINTF__

#include <hotplace/sdk/base/basic/types.hpp>
#include <string>

namespace hotplace {

//
// valist
//

/**
 * @brief   format string syntax
 * @remakrs
 *          sprintf support {1} {2} ... using valist (codename.grape Revision 371)
 *          Aho-Corasick algorithm applied (codename.hotplace Revision 607)
 *          format string syntax e.g. {1:02x} {1:3d} {2:-10s} (codename.hotplace Revision 977)
 *
 *          format specifier replacement (do not supports %c %s %d, but {1} {2} {3} ... available)
 *          standard vprintf(fmt, ap) supports ordered format specifier {1} {2} {3} ...
 *
 *          format string syntax
 *          - {n} n MUST be in 1..arg
 *          - string argument {n}, {n:-10s}, {n:10s}
 *          - integer argument {n}, {n:10d}, {n:10i}, {n:08x}
 *          - floating point argument {n}, {n:le}, {n:lf}, {n:lg}
 *
 * @example
 *          basic_stream bs;
 *          {
 *              valist va;
 *              va << 1 << "test string"; // argc 2
 *
 *              bs.clear();
 *              sprintf (&bs, "value1={1} value2={2}", va);
 *              // value1=1 value2=test string
 *              bs.clear();
 *              sprintf (&bs, "value1={2} value2={1}", va);
 *              // value1=test string value2=1
 *              bs.clear();
 *              sprintf (&bs, "value1={2} value2={1} value3={3}", va);
 *              // value1=test string value2=1 value3={3}
 *          }
 *
 *          {
 *              valist va;
 *              va << 256 << "hello world" << 3.141592;
 *
 *              bs.clear();
 *              sprintf(&bs, R"(value={1}, value={1:04x}, value={1:04d})", va);
 *              // value=256, value=0x0100, value=0256
 *              bs.clear();
 *              sprintf(&bs, R"(value="{2}", value="{2:-15s}", value="{2:15s}")", va);
 *              // value="hello world", value="hello world    ", value="    hello world"
 *              bs.clear();
 *              sprintf(&bs, R"(value={3}, value={3:le}, value={3:lg})", va);
 *              // value=3.141592, value=3.141592e+00, value=3.14159
 *              bs.clear();
 *              // {n} n MUST be in 1..arg so {-1} is ignored
 *              // {2} is a string so 10d is ignored
 *              // {3} is an integer so s is ignored
 *              sprintf(&bs, {R"(value={-1}, value="{2:10d}", value={3:s})", va);
 *              // value={-1}, value="hello world", value=3.141592
 *          }
 */
return_t sprintf(stream_t* stream, const char* fmt, valist va);

/* @brief   safe format printer (variadic template edition)
 * @remarks
 *  ansi_string str;
 *  // snippet 1
 *  valist val;
 *  make_valist (val, 1, 3.141592, "hello");
 *  sprintf (&str, "param1 {1} param2 {2} param3 {3}\n", val);
 *  // snippet 2
 *  valist va;
 *  sprintf (&str, "param1 {1} param2 {2} param3 {3}\n", va << 1 << 3.14 << "hello");
 *  // snippet 3
 *  vprintf (&str, "param1 {1} param2 {2} param3 {3}\n", 1, 3.141592, "hello");
 */

template <typename T>
void make_valist(valist& va, T arg) {
    va << arg;
}

#if __cplusplus >= 201103L  // c++11

template <typename T, typename... Args>
void make_valist(valist& va, T arg, Args... args) {
    va << arg;
    make_valist(va, args...);
}

#if __cplusplus >= 201402L  // c++14
/**
 * @brief vprintf
 * @param stream_t*     stream  [out]
 * @param const char*   fmt     [in] "param1 {1} param {2}"
 * @param Args...       args    [in] parameter pack (c++11)
 */
template <class... Args>
return_t vprintf(stream_t* stream, const char* fmt, Args... args) {
    auto s = [&stream, fmt, args...] {
        valist va;

        make_valist(va, args...);
        return sprintf(stream, fmt, va);
    };

    return s();
}

#endif  // c++14
#endif  // c++11

}  // namespace hotplace

#endif
