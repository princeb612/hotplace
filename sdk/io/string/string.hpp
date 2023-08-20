/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *      printf mbs/wcs
 *
 *
 * Revision History
 * Date         Name                Description
 * 2013.05.08   Soo Han, Kim        printf %I64i, %I64u (code.merlin)
 * 2018.06.15   Soo Han, Kim        printf %zi, %zu, %zd (code.grape)
 * 2020.02.06   Soo Han, Kim        printf %I128i, %1284u (code.unicorn)
 * 2021.06.29   Soo Han, Kim        printf unicode (code.unicorn)
 * 2023.08.13   Soo Han, Kim        reboot base16
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

#ifndef __HOTPLACE_SDK_IO_STRING_STRING__
#define __HOTPLACE_SDK_IO_STRING_STRING__

#include <hotplace/sdk/base.hpp>
//#include <hotplace/sdk/io/stream/stream.hpp>
//#include <hotplace/sdk/io/stream/buffer_stream.hpp>
#include <string>

namespace hotplace {
namespace io {

//
// part - printf
//

/**
 * @brief printf
 * @sample
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
 *      std::cout << context.str.c_str () << std::endl;
 *  }
 */

/**
 * @brief callback
 */
typedef int (*CALLBACK_PRINTFA)(void *context, const char * buf, int len);
typedef int (*CALLBACK_PRINTFW)(void *context, const wchar_t * buf, int len);

#if defined _MBCS || defined MBCS
    #define CALLBACK_PRINTF CALLBACK_PRINTFA
    #define printf_runtime    printf_runtime
    #define vprintf_runtime   vprintf_runtime
#elif defined _UNICODE || defined UNICODE
    #define CALLBACK_PRINTF CALLBACK_PRINTFW
    #define printf_runtime    printf_runtimew
    #define vprintf_runtime   vprintf_runtimew
#endif

/**
 * @brief printf
 * @param   void *          context
 * @param   CALLBACK_PRINTF runtime_printf
 * @param   const char  *   fmt0
 * @param   ...
 */
int printf_runtime (void *context, CALLBACK_PRINTFA runtime_printf, const char * fmt0, ...);
#if defined _WIN32 || defined _WIN64
int printf_runtimew (void *context, CALLBACK_PRINTFW runtime_printf, const wchar_t * fmt0, ...);
#endif
/**
 * @brief vprintf
 * @param   void *          context
 * @param   CALLBACK_PRINTF runtime_printf
 * @param   const char  *   fmt0
 * @param   va_list         ap
 */
int vprintf_runtime (void *context, CALLBACK_PRINTFA runtime_printf, const char * fmt0, va_list ap);
#if defined _WIN32 || defined _WIN64
int vprintf_runtimew (void *context, CALLBACK_PRINTFW runtime_printf, const wchar_t * fmt0, va_list ap);
#endif

//
// part - mbs2wcs and vice versa
//

#if defined _WIN32 || defined _WIN64
std::wstring A2W (const char* source, uint32 codepage = 0);
return_t A2W (std::wstring& target, const char* source, uint32 codepage = 0);

std::string W2A (const wchar_t* source, uint32 codepage = 0);
return_t W2A (std::string& target, const wchar_t* source, uint32 codepage = 0);
#endif

//
// part - utility methods
//

/**
 * @brief tokenize
 * @remarks simple to use, but not efficient
 * @sample
 *  std::string token = "=|", value;
 *  std::string data = "key=item1|value1|link1";
 *
 *  _test_case.start ();
 *
 *  gettoken (data, token, 0, value);  // "key"
 *  _test_case.assert (value == "key", __FUNCTION__, "gettoken");
 *
 *  gettoken (data, token, 1, value);  // "item1"
 *  _test_case.assert (value == "item1", __FUNCTION__, "gettoken");
 */
bool gettoken (std::string source, std::string token, size_t index, std::string& value);
#if defined _WIN32 || defined _WIN64
bool gettoken (std::wstring source, std::wstring token, size_t index, std::wstring& value);
#endif

/**
 * @brief tokenize
 * @sample
 *  std::string data = "key=item1|value1|link1";
 *  size_t pos = 0;
 *  std::string token;
 *  for (;;) {
 *      token = tokenize (data, std::string ("=|"), pos);
 *      printf ("%s\n", token.c_str ()); // in order item1, value1, link1
 *      if ((size_t) -1 == pos) {
 *          break;
 *      }
 *  }
 */
std::string tokenize (std::string source, std::string tokens, size_t& pos);
#if defined _WIN32 || defined _WIN64
std::wstring tokenize (std::wstring source, std::wstring tokens, size_t& pos);
#endif

/**
 * @brief replace
 * @sample
 *  std::string data ("hello world");
 *  replace (data, "world", "neighbor");
 */
void replace (std::string& source, std::string a, std::string b);
#if defined _WIN32 || defined _WIN64
void replace (std::wstring& source, std::wstring a, std::wstring b);
#endif


/**
 * @brief getline
 * @sample
 *  return_t ret = errorcode_t::success;
 *  const char* stream_data = " line1 \nline2 \n  line3\nline4";
 *  size_t stream_size = strlen (stream_data);
 *  size_t pos = 0;
 *  size_t brk = 0;
 *
 *  for (;;) {
 *      ret = getline (stream_data, stream_size, pos, &brk);
 *      if (errorcode_t::success != ret) {
 *          break;
 *      }
 *
 *      // line contains CR and NL
 *      //printf ("%.*s\n", brk - pos, stream_data + pos);
 *      std::string line (stream_data + pos, brk - pos);
 *      ltrim (rtrim (line));
 *      printf ("%s\n", line.c_str ());
 *
 *      pos = brk;
 *  }
 */
return_t getline (const char* stream, size_t sizestream, size_t startpos, size_t *brk);
#if defined _WIN32 || defined _WIN64
return_t getline (const wchar_t* stream, size_t sizestream, size_t startpos, size_t *brk);
#endif

/**
 * @brief scan
 * @param const char* stream [in]
 * @param size_t sizestream [in]
 * @param size_t startpos [in]
 * @param size_t *brk [out]
 * @param int (*func)(int) [in]
 * @sample
 *  const char* data = "hello world\n ";
 *  size_t pos = 0;
 *  size_t brk = 0;
 *  while (true) {
 *      ret = scan (data, strlen (data), pos, &brk, isspace);
 *      if (errorcode_t::success != ret) {
 *          break;
 *      }
 *      printf ("position isspace %zi\n", brk); // in order 6, 12, 13
 *      pos = brk;
 *  }
 */
return_t scan (const char* stream, size_t sizestream, size_t startpos, size_t *brk, int (*func)(int));
#if defined _WIN32 || defined _WIN64
return_t scan (const wchar_t* stream, size_t sizestream, size_t startpos, size_t *brk, int (*func)(int));
#endif

/**
 * @brief scan
 * @param const char* stream [in]
 * @param size_t sizestream [in]
 * @param size_t startpos [in]
 * @param size_t *brk [out]
 * @param const char* match [in]
 * @sample
 *  const char* data = "hello world\n wide world\n";
 *  const char* match = " ";
 *  size_t pos = 0;
 *  size_t brk = 0;
 *  while (true) {
 *      ret = scan (data, strlen (data), pos, &brk, match);
 *      if (errorcode_t::success != ret) {
 *          break;
 *      }
 *      printf ("position %zi\n", brk); // in order 7, 19
 *      pos = brk + strlen (match);
 *  }
 */
return_t scan (const char* stream, size_t sizestream, size_t startpos, size_t *brk, const char* match);
#if defined _WIN32 || defined _WIN64
return_t scan (const wchar_t* stream, size_t sizestream, size_t startpos, size_t *brk, const wchar_t* token);
#endif

//
// part - split
//

/**
 * @brief split
 * @sample
 *  split_context_t* handle = nullptr;
 *  size_t count = 0;
 *  split_begin (&handle, "test1.hello2.bye3..", ".");
 *  split_count (handle, count);
 *  binary_t data;
 *  for (size_t i = 0; i < count; i++) {
 *      split_get (handle, i, data);
 *      printf ("[%i] (%zi) %.*s\n", i, data.size (), data.size (), &data [0]);
 *  }
 *  split_end (handle);
 */
typedef struct _split_map_item {
    uint32 begin;
    uint32 length;
} split_map_item;
typedef std::list<split_map_item> split_map_list;
typedef struct _split_context_t {
    std::string source;
    split_map_list info;
} split_context_t;
return_t split_begin (split_context_t** handle, const char* str, const char* delim);
return_t split_count (split_context_t* handle, size_t& result);
return_t split_get (split_context_t* handle, unsigned int index, binary_t& data);
return_t split_get (split_context_t* handle, unsigned int index, std::string& data);
return_t split_end (split_context_t* handle);

//
// part - format
//

/**
 * @brief format
 * @sample
 *  std::string text = format ("%s %d %1.1f\n", "sample", 1, 1.1f);
 */
std::string format (const char* fmt, ...);
#if __cplusplus > 199711L    // c++98
std::string format (const char* fmt, va_list ap);
#endif

}
}

#endif