/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   value.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_NOSTD_VALUE__
#define __HOTPLACE_SDK_BASE_NOSTD_VALUE__

// remove future
// - MSVC Concurrency::detail::_RefCounter
// - valgrind drd compatibility
#include <hotplace/sdk/base/basic/types.hpp>
#include <string>

namespace hotplace {

/**
 * @brief   value
 */
template <typename T>
class t_value {
   public:
    t_value() : _value(T()), _cached(false) {}

    t_value(const t_value& other) {
        _value = other._value;
        _cached = other._cached;
        _name = other._name;
    }
    t_value& operator=(const t_value& other) {
        if (this != &other) {
            _value = other._value;
            _cached = other._cached;
            _name = other._name;
        }
        return *this;
    }

    t_value(t_value&& other) noexcept { *this = std::move(other); }
    t_value& operator=(t_value&& other) noexcept {
        if (this != &other) {
            _value = std::move(other._value);
            _cached = other._cached;
            _name = std::move(other._name);
        }
        return *this;
    }

    t_value(const T& value, const std::string& name = "") : _value(value), _cached(true), _name(name) {}
    t_value& operator=(const T& value) {
        set_value(value);
        return *this;
    }

    t_value(T&& value, std::string&& name = "") : _value(std::move(value)), _cached(true), _name(std::move(name)) {}
    t_value& operator=(T&& value) {
        set_value(std::move(value));
        return *this;
    }

    ~t_value() {}

    T value(bool usecache = true) const {
        if (usecache && _cached) {
            return _value;
        }
        return _value;
    }

    operator T() const { return value(); }

    t_value& set_value(const T& value) {
        _value = value;
        _cached = true;
        return *this;
    }

    t_value& set_value(T&& value) {
        _value = std::move(value);
        _cached = true;
        return *this;
    }

    t_value& set_name(const std::string& name) {
        _name = name;
        return *this;
    }

    const std::string& get_name() const { return _name; }
    bool is_named() const { return false == _name.empty(); }

    bool operator<(const t_value& other) const { return this->value() < other.value(); }
    bool operator<=(const t_value& other) const { return this->value() <= other.value(); }
    bool operator>(const t_value& other) const { return this->value() > other.value(); }
    bool operator>=(const t_value& other) const { return this->value() >= other.value(); }
    bool operator==(const t_value& other) const { return this->value() == other.value(); }
    bool operator!=(const t_value& other) const { return this->value() != other.value(); }

   private:
    mutable T _value = T();
    mutable bool _cached{false};
    std::string _name;
};

}  // namespace hotplace

#endif
