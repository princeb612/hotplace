/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_STRING_STRING__
#define __HOTPLACE_SDK_IO_STRING_STRING__

#include <sdk/base.hpp>
#include <string>

namespace hotplace {
namespace io {

//
// part - mbs2wcs and vice versa (Windows)
//

#if defined _WIN32 || defined _WIN64
std::wstring A2W(const char* source, uint32 codepage = 0);
return_t A2W(std::wstring& target, const char* source, uint32 codepage = 0);

std::string W2A(const wchar_t* source, uint32 codepage = 0);
return_t W2A(std::string& target, const wchar_t* source, uint32 codepage = 0);
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
bool gettoken(const std::string& source, const std::string& token, size_t index, std::string& value);
#if defined _WIN32 || defined _WIN64
bool gettoken(const std::wstring& source, const std::wstring& token, size_t index, std::wstring& value);
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
enum tokenize_mode_t {
    token_quoted = 1,
};
std::string tokenize(const std::string& source, const std::string& tokens, size_t& pos, int mode = 0);
#if defined _WIN32 || defined _WIN64
std::wstring tokenize(const std::wstring& source, const std::wstring& tokens, size_t& pos, int mode = 0);
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

//
// std::regex
//

/**
 * @brief   regular expression
 * @param   const std::string& input [in]
 * @param   const std::string& expr [in]
 * @param   size_t& pos [out]
 * @param   std::list<std::string>& tokens [out]
 * @sa      split_url
 */
void regex_token(const std::string& input, const std::string& expr, size_t& pos, std::list<std::string>& tokens);

/**
 * @brief  escape_url
 * @param  const char* url [in]
 * @param  stream_t* s [out]
 * @param  uint32 flags [inopt] reserved
 */
return_t escape_url(const char* url, stream_t* s, uint32 flags = 0);
/**
 * @brief unescape
 * @param  const char* url [in]
 * @param  stream_t* s [out]
 * @example
 *        basic_stream bs;
 *        unescape("https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb", &bs);
 *        std::cout << bs << std::endl; // https://client.example.com/cb
 */
return_t unescape_url(const char* url, stream_t* s);

//
// split_url
//
typedef struct _url_info_t {
    std::string scheme;
    std::string host;
    int port;
    std::string uri;
    std::string uripath;
    std::string query;
    std::string fragment;

    _url_info_t() : port(0) {}

    void clear() {
        scheme.clear();
        host.clear();
        port = 0;
        uri.clear();
        uripath.clear();
        query.clear();
        fragment.clear();
    }
} url_info_t;

/**
 * @brief   split url
 * @param   const char* url [in]
 * @param   url_info_t* info [out]
 * @example
 *        url_info_t info;
 *        const char *url = "http://test.com/resource?client_id=12345#part1";
 *        split_url(url, &info);
 *        // info.protocol => http
 *        // info.host => test.com
 *        // info.port => 80
 *        // info.uri => /resource?client_id=12345
 *        // info.uripath => /resource
 *        // info.query => client_id=12345
 *        // info.fragment => part1
 */
return_t split_url(const char* url, url_info_t* info);

}  // namespace io
}  // namespace hotplace

#endif
