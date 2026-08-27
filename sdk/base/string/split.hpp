/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   split.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_STRING_SPLIT__
#define __HOTPLACE_SDK_BASE_STRING_SPLIT__

#include <functional>
#include <hotplace/sdk/base/basic/types.hpp>
#include <string>
#include <vector>

namespace hotplace {

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
 *      printf ("[%i] (%zi) %.*s\n", i, data.size (), data.size (), data.data());
 *  }
 *  split_end (handle);
 */
typedef struct _split_map_item {
    size_t begin;
    size_t length;
} split_map_item;
typedef std::vector<split_map_item> split_map_list;
typedef struct _split_context_t {
    std::string source;
    split_map_list info;
} split_context_t;
return_t split_begin(split_context_t** handle, const char* str, const char* delim);
return_t split_count(split_context_t* handle, size_t& result);
return_t split_get(split_context_t* handle, size_t index, binary_t& data);
return_t split_get(split_context_t* handle, size_t index, std::string& data);
return_t split_end(split_context_t* handle);
template <typename F>  // void(const std::string&)
return_t split_foreach(split_context_t* handle, F func) {
    if (nullptr == handle) return errorcode_t::invalid_parameter;

    for (const auto& item : handle->info) {
        std::string data;
        data.assign(handle->source.c_str() + item.begin, item.length);
        func(data);
    }
    return errorcode_t::success;
}
template <typename F>  // bool(const std::string&)
return_t split_chained_foreach(split_context_t* handle, F func) {
    if (nullptr == handle) return errorcode_t::invalid_parameter;

    for (const auto& item : handle->info) {
        std::string data;
        data.assign(handle->source.c_str() + item.begin, item.length);
        auto check = func(data);
        if (false == check) {
            return errorcode_t::internal_error;
        }
    }
    return errorcode_t::success;
}

}  // namespace hotplace

#endif
