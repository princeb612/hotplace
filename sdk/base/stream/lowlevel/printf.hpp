/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   printf.hpp
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

#ifndef __HOTPLACE_SDK_BASE_STREAM_LOWLEVEL_PRINTF__
#define __HOTPLACE_SDK_BASE_STREAM_LOWLEVEL_PRINTF__

#include <hotplace/sdk/base/basic/types.hpp>
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
typedef int (*CALLBACK_PRINTFA)(printf_context_t* context, const char* buf, int len);
typedef int (*CALLBACK_PRINTFW)(printf_context_t* context, const wchar_t* buf, int len);

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
int printf_runtime(printf_context_t* context, CALLBACK_PRINTFA runtime_printf, const char* fmt0, ...);
#if defined _WIN32 || defined _WIN64
int printf_runtimew(printf_context_t* context, CALLBACK_PRINTFW runtime_printf, const wchar_t* fmt0, ...);
#endif
/**
 * @brief vprintf
 * @param   printf_context_t *          context
 * @param   CALLBACK_PRINTF runtime_printf
 * @param   const char  *   fmt0
 * @param   va_list         ap
 */
int vprintf_runtime(printf_context_t* context, CALLBACK_PRINTFA runtime_printf, const char* fmt0, va_list ap);
#if defined _WIN32 || defined _WIN64
int vprintf_runtimew(printf_context_t* context, CALLBACK_PRINTFW runtime_printf, const wchar_t* fmt0, va_list ap);
#endif

}  // namespace hotplace

#endif
