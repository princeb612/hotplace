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

#include <functional>
#include <map>
#include <sdk/base/binary.hpp>
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
class t_maphint {
   public:
    t_maphint(std::map<K, V>& source) : _source(source) {
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
class t_maphint_const {
   public:
    t_maphint_const(std::map<K, V> const& source) : _source(source) {
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

/**
 * @brief   delete
 * @example
 *          char* text = new char[10];
 *          delete [] text;
 *
 *          char* text = new char[10];
 *          t_promise_on_destroy<char*>(text, [](char* p) -> void { delete [] p; });
 *
 *          FILE* fp = fopen(...);
 *          t_promise_on_destroy<FILE*>(fp, [](FILE* file) -> void { fclose(file); });
 */
template <typename TYPE_PTR>
class t_promise_on_destroy {
   public:
    t_promise_on_destroy(TYPE_PTR object, std::function<void(TYPE_PTR)> func) : _object(object), _function(func) {}
    ~t_promise_on_destroy() {
        if (_object && _function) {
            _function(_object);
        }
    }

   private:
    TYPE_PTR _object;
    std::function<void(TYPE_PTR)> _function;
};

}  // namespace hotplace

#endif
