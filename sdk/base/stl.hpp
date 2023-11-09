/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_STL__
#define __HOTPLACE_SDK_BASE_STL__

#include <map>
#include <sdk/base/error.hpp>
#include <sdk/base/types.hpp>

namespace hotplace {

/**
 * @brief   format
 * @example
 *  std::string text = format ("%s %d %1.1f\n", "sample", 1, 1.1f);
 */
std::string format(const char* fmt, ...);
#if __cplusplus > 199711L  // c++98
std::string format(const char* fmt, va_list ap);
#endif

/**
 * @brief   util
 */
template <typename K, typename V>
class maphint {
   public:
    maphint(std::map<K, V>& source) : _source(source) {
        // do nothing
    }

    return_t find(K const& key, V* value) {
        return_t ret = errorcode_t::success;

        if (value) {
            typename std::map<K, V>::iterator iter = _source.find(key);
            if (_source.end() == iter) {
                ret = errorcode_t::not_found;
            } else {
                *value = iter->second;
            }
        } else {
            ret = errorcode_t::invalid_parameter;
        }
        return ret;
    }

   private:
    std::map<K, V>& _source;
};

template <typename K, typename V>
class maphint_const {
   public:
    maphint_const(std::map<K, V> const& source) : _source(source) {
        // do nothing
    }

    return_t find(K const& key, V* value) {
        return_t ret = errorcode_t::success;

        if (value) {
            typename std::map<K, V>::const_iterator iter = _source.find(key);
            if (_source.end() == iter) {
                ret = errorcode_t::not_found;
            } else {
                *value = iter->second;
            }
        } else {
            ret = errorcode_t::invalid_parameter;
        }
        return ret;
    }

   private:
    std::map<K, V> const& _source;
};

}  // namespace hotplace

#endif
