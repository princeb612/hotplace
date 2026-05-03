/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   template.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_NOSTD_TEMPLATE__
#define __HOTPLACE_SDK_BASE_NOSTD_TEMPLATE__

#include <algorithm>
#include <functional>
#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/nostd/exception.hpp>
#include <limits>
#include <memory>
#include <set>
#include <type_traits>

namespace hotplace {

/**
 * @brief   narrow cast
 * @refer   Gemini
 */
template <typename SOURCE, bool debug_except = false>
struct t_narrow_cast_t {
    const SOURCE value;

    template <typename TYPE>
    operator TYPE() const {
#ifdef DEBUG
        if (debug_except) {
            TYPE converted = static_cast<TYPE>(value);
            if (static_cast<SOURCE>(converted) != value) {
                /**
                 * case.1
                 *  int32 i32 = -1;
                 *  uint8 ui8 = t_intended_narrow_cast(i32);
                 * case.2
                 *  int32 i32 = 300;
                 *  int8 i8 = t_intended_narrow_cast(i32);
                 */
                throw exception(errorcode_t::miscast_narrow);
            }
            if (std::numeric_limits<SOURCE>::is_signed != std::numeric_limits<TYPE>::is_signed) {
                if ((value < 0) != (converted < 0)) {
                    /**
                     * case.3
                     *  uint32 ui32 = 4294967295;
                     *  int32 i32 = t_intended_narrow_cast(ui32);
                     */
                    throw exception(errorcode_t::miscast_narrow);
                }
            }
        }
#endif
        return static_cast<TYPE>(value);
    }
};

template <typename TYPE>
constexpr t_narrow_cast_t<TYPE, true> t_narrow_cast(TYPE v) {
    return {v};
}

template <typename TYPE>
constexpr t_narrow_cast_t<TYPE, false> t_justdoit(TYPE v) {
    return {v};
}

/**
 * @example
 *          signed value;
 *          value = -value;
 */
template <typename TYPE>
typename std::enable_if<std::numeric_limits<TYPE>::is_signed, TYPE>::type t_change_sign(TYPE i) {
    return -i;
}

/**
 * @example
 *          unsigned value;
 *          value = -value;
 */
template <typename TYPE>
typename std::enable_if<!std::numeric_limits<TYPE>::is_signed, TYPE>::type t_change_sign(TYPE i) {
    throw exception(miscast_unsigned);
    return i;
}

#if __cplusplus >= 201402L  // c++14
using std::make_unique;
#else
template <typename T, typename... Args>
std::unique_ptr<T> make_unique(Args&&... args) {
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}
#endif

template <typename T>
struct t_comparator_base {
    // friend bool operator<(const T& lhs, const T& rhs) { return lhs < rhs; }
    bool operator()(const T& lhs, const T& rhs) const { return lhs < rhs; }
};

template <typename T>
struct t_type_comparator : t_comparator_base<T> {
    bool operator()(const T& lhs, const T& rhs) { return lhs.symbol < rhs.symbol; }
};

/**
 * @brief   atoi (int128)
 * @sample
 *          int128 i = 170141183460469231731687303715884105727; // warning
 *          i = t_atoi<int128>("170141183460469231731687303715884105727");
 *          i = t_atoi<int128>("-170141183460469231731687303715884105728");
 *
 *          basic_stream bs;
 *          bs.printf("%40I128i %032I128x", i, i);
 *
 *          //  170141183460469231731687303715884105727 7fffffffffffffffffffffffffffffff
 *          // -170141183460469231731687303715884105728 80000000000000000000000000000000
 */
template <typename TYPE>
TYPE t_atoi_n(const char* value, size_t size) {
    return_t ret = errorcode_t::success;
    TYPE res = 0;

    __try2 {
        if (nullptr == value) {
            __leave2;
        }

        size_t i = 0;
        int sign = 0;

        if (value[i] == '-') {
            ++i;
            bool is_signed = TYPE(-1) < TYPE(0);
            if (is_signed) {
                sign = -1;
            } else {
                throw exception(errorcode_t::miscast_unsigned);
            }
        }

        if (value[i] == '+') {
            ++i;
        }

        for (; i < size; ++i) {
            const char c = value[i];
            if (0 == std::isdigit(c)) {
                ret = errorcode_t::bad_data;
                break;
            }
            res *= 10;
            res += (c - '0');
        }

        if (errorcode_t::success != ret) {
            res = 0;
            __leave2;
        }

        if (sign < 0) {
            res = t_change_sign<TYPE>(res);
        }
    }
    __finally2 {}
    return res;
}

template <typename TYPE>
TYPE t_atoi(const std::string& value) {
    return t_atoi_n<TYPE>(value.c_str(), value.size());
}

/**
 * @return  unsigned integer value
 * @sa      t_atoi for signed/unsigned
 */
template <typename T>
T t_htoi(const char* hex) {
    T value = 0;
    const char* p = hex;
    char c = 0;
    int i = 0;
    while (0 != (c = *p++)) {
        value <<= 4;
        if ('0' <= c && c <= '9') {
            i = c - '0';
        } else if ('A' <= c && c <= 'F') {
            i = c - 'A' + 10;
        } else if ('a' <= c && c <= 'f') {
            i = c - 'a' + 10;
        }
        value += i;
    }
    return value;
}

/**
 * @brief   byte capacity for signed integer
 * @sa      byte_capacity for unsigned integer
 * @remarks
 *          min -(1 << (8 * n - 1))
 *          max (1 << (8 * n - 1)) - 1
 *
 *          e.g. if n = 1, -2^7 ~ 2^7 - 1
 *
 *          1 bytes : -128 ~ 127
 *          2 bytes : -32768 ~ 32767 (exclude -128 ~ 127)
 *          3 bytes : -8388608 ~ 8388607 (exclude -32768 ~ 32767)
 *          4 bytes : -2147483648 ~ 2147483647 (exclude -8388608 ~ 8388607)
 *          5 bytes : -549755813888 ~ 549755813887 (exclude -2147483648 ~ 2147483647)
 *          6 bytes : -140737488355328 ~ 140737488355327 (exclude -549755813888 ~ 549755813887)
 *          7 bytes : -36028797018963968 ~ 36028797018963967 (exclude -140737488355328 ~ 140737488355327)
 *          8 bytes : -9223372036854775808 ~ 9223372036854775807 (exclude -36028797018963968 ~ 36028797018963967)
 *          ...
 * @example
 *          int byte_size = t_byte_capacity_signed<int128>(t_atoi<int128>("170141183460469231731687303715884105727"));
 */
template <typename signed_type>
int t_byte_capacity_signed(signed_type v) {
    int len = 1;
    if (v < 0) {
        v = ~v;  // 2's complement
    }
    while (v >>= 1) {
        len++;
    }
    return (len + 8) / 8;
}

static inline int byte_capacity(int16 v) { return t_byte_capacity_signed<int16>(v); }

static inline int byte_capacity(int32 v) { return t_byte_capacity_signed<int32>(v); }

static inline int byte_capacity(int64 v) { return t_byte_capacity_signed<int64>(v); }

#if defined __SIZEOF_INT128__
static inline int byte_capacity(int128 v) { return t_byte_capacity_signed<int128>(v); }
#endif

/**
 * @brief   util
 */
template <typename K, typename V>
class t_maphint {
   public:
    t_maphint(std::map<K, V>& source) : _source(source) {}

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
    t_maphint_const(std::map<K, V> const& source) : _source(source) {}

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

enum seek_t {
    seek_begin = 0,
    seek_move = 1,
    seek_end = 2,
};

/**
 * @remarks
 *          where  0 seek_begin, 1 seek_set, 2 seek_end
 */

template <typename container_t>
void for_each_const(const container_t& c, typename std::function<void(typename container_t::const_iterator, int)> f) {
    if (c.size()) {
        auto iter = c.begin();
        f(iter++, seek_t::seek_begin);
        while (c.end() != iter) {
            f(iter++, seek_t::seek_move);
        }
        f(c.end(), seek_t::seek_end);
    }
}

template <typename container_t>
void for_each(container_t& c, typename std::function<void(typename container_t::iterator, int)> f) {
    if (c.size()) {
        auto iter = c.begin();
        f(iter++, seek_t::seek_begin);
        while (c.end() != iter) {
            f(iter++, seek_t::seek_move);
        }
        f(c.end(), seek_t::seek_end);
    }
}

template <typename container_t, typename usertype>
void for_each_const(const container_t& c, typename std::function<void(typename container_t::const_iterator, int, usertype&)> f, usertype& u) {
    if (c.size()) {
        auto iter = c.begin();
        f(iter++, seek_t::seek_begin, u);
        while (c.end() != iter) {
            f(iter++, seek_t::seek_move, u);
        }
        f(c.end(), seek_t::seek_end, u);
    }
}

template <typename container_t, typename usertype>
void for_each(container_t& c, typename std::function<void(typename container_t::iterator, int, usertype&)> f, usertype& u) {
    if (c.size()) {
        auto iter = c.begin();
        f(iter++, seek_t::seek_begin, u);
        while (c.end() != iter) {
            f(iter++, seek_t::seek_move, u);
        }
        f(c.end(), seek_t::seek_end, u);
    }
}

/**
 * @brief   util
 * @sample
 *          std::list<int> result = {1, 2, 3};
 *          basic_stream bs;
 *          print<std::list<int>, basic_stream>(result, bs);
 *          std::cout << bs << std::endl; // [1, 2, 3]
 *
 *          std::set<int> result = {2, 3, 4};
 *          basic_stream bs;
 *          print<std::set<int>, basic_stream>(result, bs);
 *          std::cout << bs << std::endl; // [2, 3, 4]
 */
template <typename container_t, typename stream_type>
void print(const container_t& c, stream_type& s, const std::string& mark_prologue = "[", const std::string& mark_delimiter = ", ",
           const std::string& mark_epilogue = "]") {
    auto lambda = [&](typename container_t::const_iterator iter, int where) -> void {
        switch (where) {
            case seek_t::seek_begin:
                s << mark_prologue << *iter;
                break;
            case seek_t::seek_move:
                s << mark_delimiter << *iter;
                break;
            case seek_t::seek_end:
                s << mark_epilogue;
                break;
        }
    };
    for_each_const<container_t>(c, lambda);
}

template <typename container_t, typename stream_type>
void print_pair(const container_t& c, stream_type& s, const std::string& mark_prologue = "[", const std::string& mark_delimiter = ", ",
                const std::string& mark_epilogue = "]") {
    auto lambda = [&](typename container_t::const_iterator iter, int where) -> void {
        switch (where) {
            case seek_t::seek_begin:
                s << mark_prologue << "{" << iter->first << "," << iter->second << "}";
                break;
            case seek_t::seek_move:
                s << mark_delimiter << "{" << iter->first << "," << iter->second << "}";
                break;
            case seek_t::seek_end:
                s << mark_epilogue;
                break;
        }
    };
    for_each_const<container_t>(c, lambda);
}

/**
 * @brief   util
 * @sample
 *          typedef std::unordered_map<BT, trienode*> children_t;
 *          auto handler = [&](typename children_t::const_iterator iter, basic_stream& bs) -> void {
 *              bs.printf("%c, %p", iter->first, iter->second);
 *          };
 *          print_pair<children_t, basic_stream>(node->children, bs, handler);
 *          _logger->writeln("children : %s", bs.c_str());
 */
template <typename container_t, typename stream_type>
void print_pair(const container_t& c, stream_type& s, std::function<void(typename container_t::const_iterator, stream_type&)> f, const std::string& mark_prologue = "[",
                const std::string& mark_delimiter = ", ", const std::string& mark_epilogue = "]") {
    auto lambda = [&](typename container_t::const_iterator iter, int where) -> void {
        switch (where) {
            case seek_t::seek_begin:
                s << mark_prologue << "{";
                f(iter, s);
                s << "}";
                break;
            case seek_t::seek_move:
                s << mark_delimiter << "{";
                f(iter, s);
                s << "}";
                break;
            case seek_t::seek_end:
                s << mark_epilogue;
                break;
        }
    };
    for_each_const<container_t>(c, lambda);
}

/**
 * @brief   find_lessthan_or_equal
 */
template <typename T>
void find_lessthan_or_equal(std::set<T>& container, const T& point, T& value) {
    auto iter = std::lower_bound(container.begin(), container.end(), point);
    if ((container.begin() == iter) && (*iter > point)) {
        value = T();
    } else if ((container.end() == iter) || (*iter > point)) {
        value = *(--iter);
    } else {
        value = *iter;
    }
}

}  // namespace hotplace

#endif
