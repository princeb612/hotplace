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

#include <sdk/base.hpp>
#include <string>

namespace hotplace {

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
return_t split_begin(split_context_t** handle, const char* str, const char* delim);
return_t split_count(split_context_t* handle, size_t& result);
return_t split_get(split_context_t* handle, unsigned int index, binary_t& data);
return_t split_get(split_context_t* handle, unsigned int index, std::string& data);
return_t split_end(split_context_t* handle);

}  // namespace hotplace

#endif
