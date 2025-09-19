/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_STRING_STRING__
#define __HOTPLACE_SDK_BASE_STRING_STRING__

#include <functional>
#include <hotplace/sdk/base/charset.hpp>
#include <hotplace/sdk/base/error.hpp>
#include <hotplace/sdk/base/syntax.hpp>
#include <hotplace/sdk/base/types.hpp>
#include <string>
#include <vector>

namespace hotplace {

/**
 * @brief   format
 * @example
 *  std::string text = format ("%s %d %1.1f\n", "sample", 1, 1.1f);
 */
std::string format(const char* fmt, ...);
std::string format(const char* fmt, va_list ap);

/**
 * @brief replace
 * @example
 *  std::string data ("hello world");
 *  replace (data, "world", "neighbor");
 */
void replace(std::string& source, const std::string& a, const std::string& b);
#if defined _WIN32 || defined _WIN64
void replace(std::wstring& source, const std::wstring& a, const std::wstring& b);
#endif

/**
 * @brief scan
 * @param const char* stream [in]
 * @param size_t sizestream [in]
 * @param size_t startpos [in]
 * @param size_t *brk [out]
 * @param int (*func)(int) [in]
 * @example
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
return_t scan(const char* stream, size_t sizestream, size_t startpos, size_t* brk, int (*func)(int));
#if defined _WIN32 || defined _WIN64
return_t scan(const wchar_t* stream, size_t sizestream, size_t startpos, size_t* brk, int (*func)(int));
#endif

/**
 * @brief scan
 * @param const char* stream [in]
 * @param size_t sizestream [in]
 * @param size_t startpos [in]
 * @param size_t *brk [out]
 * @param const char* match [in]
 * @example
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
return_t scan(const char* stream, size_t sizestream, size_t startpos, size_t* brk, const char* match);
#if defined _WIN32 || defined _WIN64
return_t scan(const wchar_t* stream, size_t sizestream, size_t startpos, size_t* brk, const wchar_t* token);
#endif

/**
 * @brief getline
 * @example
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
return_t getline(const char* stream, size_t sizestream, size_t startpos, size_t* brk);
#if defined _WIN32 || defined _WIN64
return_t getline(const wchar_t* stream, size_t sizestream, size_t startpos, size_t* brk);
#endif

//
// part - split
//

/**
 * @brief split
 * @example
 *  split_context_t* handle = nullptr;
 *  size_t count = 0;
 *  split_begin (&handle, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256", ":");
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
typedef std::vector<split_map_item> split_map_list;
typedef struct _split_context_t {
    std::string source;
    split_map_list info;
} split_context_t;
return_t split_begin(split_context_t** handle, const char* str, const char* delim);
return_t split_count(split_context_t* handle, size_t& result);
return_t split_get(split_context_t* handle, unsigned int index, binary_t& data);
return_t split_get(split_context_t* handle, unsigned int index, std::string& data);
return_t split_end(split_context_t* handle);
return_t split_foreach(split_context_t* handle, std::function<void(const std::string&)> func);

}  // namespace hotplace

#endif
