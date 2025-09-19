/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * printf license
 *  Copyright (c) 1990 Regents of the University of California.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms are permitted
 *  provided that the above copyright notice and this paragraph are
 *  duplicated in all such forms and that any documentation,
 *  advertising materials, and other materials related to such
 *  distribution and use acknowledge that the software was developed
 *  by the University of California, Berkeley.  The name of the
 *  University may not be used to endorse or promote products derived
 *  from this software without specific prior written permission.
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 *  IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

#ifndef __HOTPLACE_SDK_BASE_STREAM_PRINTF__
#define __HOTPLACE_SDK_BASE_STREAM_PRINTF__

#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/basic/valist.hpp>
#include <string>

namespace hotplace {

struct printf_context_t {
    uint8 indent;

    printf_context_t() : indent(0) {}
};

/**
 * @brief printf
 * @example
 *  typedef struct {
 *      std::string str;
 *  } myprintf_context_t;
 *
 *  int callback_printf (void* context, const char* buf, int len)
 *  {
 *      myprintf_context_t* handle = (myprintf_context_t*)context;
 *      handle->str.append (buf, len);
 *      return 0;
 *  }
 *
 *  void test_printf ()
 *  {
 *      myprintf_context_t context;
 *      printf_runtime (&context, &callback_printf, "%s %i %1.1f", "sample", 1, 1.1);
 *      std::cout << context.str << std::endl;
 *  }
 */

/**
 * @brief callback
 */
typedef int (*CALLBACK_PRINTFA)(printf_context_t *context, const char *buf, int len);
typedef int (*CALLBACK_PRINTFW)(printf_context_t *context, const wchar_t *buf, int len);

#if defined _MBCS || defined MBCS
#define CALLBACK_PRINTF CALLBACK_PRINTFA
#define printf_runtime printf_runtime
#define vprintf_runtime vprintf_runtime
#elif defined _UNICODE || defined UNICODE
#define CALLBACK_PRINTF CALLBACK_PRINTFW
#define printf_runtime printf_runtimew
#define vprintf_runtime vprintf_runtimew
#endif

/**
 * @brief printf
 * @param   printf_context_t *          context
 * @param   CALLBACK_PRINTF runtime_printf
 * @param   const char  *   fmt0
 * @param   ...
 */
int printf_runtime(printf_context_t *context, CALLBACK_PRINTFA runtime_printf, const char *fmt0, ...);
#if defined _WIN32 || defined _WIN64
int printf_runtimew(printf_context_t *context, CALLBACK_PRINTFW runtime_printf, const wchar_t *fmt0, ...);
#endif
/**
 * @brief vprintf
 * @param   printf_context_t *          context
 * @param   CALLBACK_PRINTF runtime_printf
 * @param   const char  *   fmt0
 * @param   va_list         ap
 */
int vprintf_runtime(printf_context_t *context, CALLBACK_PRINTFA runtime_printf, const char *fmt0, va_list ap);
#if defined _WIN32 || defined _WIN64
int vprintf_runtimew(printf_context_t *context, CALLBACK_PRINTFW runtime_printf, const wchar_t *fmt0, va_list ap);
#endif

//
// valist
//

/**
 * @brief   safe format printer
 * @remakrs
 *          format specifier replacement (do not supports %c %s %d, but {1} {2} {3} ... available)
 *          standard vprintf(fmt, ap) supports ordered format specifier {1} {2} {3} ...
 * @example
 *          basic_stream bs;
 *          valist va;
 *          va << 1 << "test string"; // argc 2
 *          sprintf (&bs, "value1={1} value2={2}", va); // value1=1 value2=test string
 *          sprintf (&bs, "value1={2} value2={1}", va); // value1=test string value2=1
 *          sprintf (&bs, "value1={2} value2={1} value3={3}", va); // value1=test string value2=1 value3={3}
 */
return_t sprintf(stream_t *stream, const char *fmt, valist va);

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
void make_valist(valist &va, T arg) {
    va << arg;
}

#if __cplusplus >= 201103L  // c++11

template <typename T, typename... Args>
void make_valist(valist &va, T arg, Args... args) {
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
return_t vprintf(stream_t *stream, const char *fmt, Args... args) {
    auto s = [&stream, fmt, args...] {
        valist va;

        make_valist(va, args...);
        return sprintf(stream, fmt, va);
    };

    return s();
}

#endif  // c++14
#endif  // c++11

//
// variant_t
//

/**
 * @brief printf variant_t
 * @example
 *  basic_stream bs;
 *  variant_t v;
 *
 *  variant_set_int32 (v, 10);
 *  vtprintf (&bs, v);
 *
 *  variant_set_str_new (v, "sample");
 *  vtprintf (&bs, v);
 *  variant_free (v);
 *
 *  std::cout << bs << std::endl;
 */
enum vtprintf_style_t {
    vtprintf_style_normal = 0,
    vtprintf_style_cbor = 1,
    vtprintf_style_base16 = 2,
    vtprintf_style_debugmode = 3,
};
return_t vtprintf(stream_t *stream, const variant_t &vt, vtprintf_style_t style = vtprintf_style_normal);
return_t vtprintf(stream_t *stream, const variant &vt, vtprintf_style_t style = vtprintf_style_normal);

}  // namespace hotplace

#endif
