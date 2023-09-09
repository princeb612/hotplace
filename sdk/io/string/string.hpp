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
 */

#ifndef __HOTPLACE_SDK_IO_STRING_STRING__
#define __HOTPLACE_SDK_IO_STRING_STRING__

#include <hotplace/sdk/base.hpp>
#include <string>

namespace hotplace {
namespace io {

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
 * @example
 *  std::string token = "=|", value;
 *  std::string data = "key=item1|value1|link1";
 *
 *  _test_case.reset_time ();
 *
 *  gettoken (data, token, 0, value);  // "key"
 *  _test_case.assert (value == "key", __FUNCTION__, "gettoken");
 *
 *  gettoken (data, token, 1, value);  // "item1"
 *  _test_case.assert (value == "item1", __FUNCTION__, "gettoken");
 */
bool gettoken (std::string const& source, std::string const& token, size_t index, std::string& value);
#if defined _WIN32 || defined _WIN64
bool gettoken (std::wstring const& source, std::wstring const& token, size_t index, std::wstring& value);
#endif

/**
 * @brief tokenize
 * @example
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
std::string tokenize (std::string const& source, std::string const& tokens, size_t& pos);
#if defined _WIN32 || defined _WIN64
std::wstring tokenize (std::wstring const& source, std::wstring const& tokens, size_t& pos);
#endif

/**
 * @brief replace
 * @example
 *  std::string data ("hello world");
 *  replace (data, "world", "neighbor");
 */
void replace (std::string& source, std::string const& a, std::string const& b);
#if defined _WIN32 || defined _WIN64
void replace (std::wstring& source, std::wstring const& a, std::wstring const& b);
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
return_t scan (const char* stream, size_t sizestream, size_t startpos, size_t *brk, const char* match);
#if defined _WIN32 || defined _WIN64
return_t scan (const wchar_t* stream, size_t sizestream, size_t startpos, size_t *brk, const wchar_t* token);
#endif

//
// part - split
//

/**
 * @brief split
 * @example
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
// split_url
//
typedef struct _url_info_t {
    std::string protocol;
    std::string domainip;
    int port;
    std::string uri;
    std::string uripath;
    std::string urifile;

    _url_info_t () : port (0)
    {
    }
} url_info_t;

/**
 * split url
 * @example
 *        url_info_t info;
 *        const char *url = "http://test.com/download/meta/file.txt";
 *        split_url(url, &info);
 *        // info.protocol => http
 *        // info.domainip => test.com
 *        // info.port => 80
 *        // info.uri => /download/meta/file.txt
 *        // info.uripath => download/meta
 *        // info.urifile => file.txt
 * @remarks
 *        input                             -> prot / domainip / uripath  / urifile
 *        http://test.com/download/file.txt -> http / test.com / download / file.txt
 *        http://test.com/download/         -> http / test.com / download / NA
 *        http://test.com/download          -> http / test.com / NA       / download
 *        http://test.com/a/b/              -> http / test.com / a/b      / NA
 *        http://test.com/a/b               -> http / test.com / a        / b
 *        http://test.com                   -> http / test.com / NA       / NA
 *        /download/file.txt                -> NA   / NA       / download / file.txt
 *        /download/                        -> NA   / NA       / download / N/A
 */
return_t split_url (const char* url, url_info_t* info);

}
}

#endif
