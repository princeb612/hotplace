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

#include <future>
#include <hotplace/sdk/base/basic/types.hpp>
#include <string>

namespace hotplace {

/**
 * @brief   value
 * @remarks not exception-sensitive
 */
template <typename T>
class t_value {
   public:
    t_value() : _defer(false), _value(T()), _cached(false) {}

    // copy constructor (excludes _promise and _future)
    t_value(const t_value& other) {
        _defer = other._defer;
        _value = other.value();  // Ensure value is evaluated/cached if deferred
        _cached = other._cached;
        _name = other._name;
        // _promise and _future remain default-initialized (not copied)
    }
    // copy assignment operator (excludes _promise and _future)
    t_value& operator=(const t_value& other) {
        if (this != &other) {
            _defer = other._defer;
            _value = other.value();  // Ensure value is evaluated/cached if deferred
            _cached = other._cached;
            _name = other._name;
            // _promise and _future remain unchanged or can be reset if needed
        }
        return *this;
    }

    t_value(t_value&& other) noexcept { *this = std::move(other); }
    t_value& operator=(t_value&& other) noexcept {
        if (this != &other) {
            _defer = std::move(other._defer);
            _value = std::move(other._value);
            _promise = std::move(other._promise);
            _future = std::move(other._future);
            _cached = other._cached;
            _name = std::move(other._name);
        }
        return *this;
    }
    t_value(const T& value, const std::string& name = "", bool defer = false) : _defer(defer), _value(value), _cached(true), _name(name) { set_value(value); }
    t_value& operator=(const T& value) {
        set_value(value);
        return *this;
    }

    t_value(T&& value, std::string&& name = "", bool defer = false) : _defer(defer), _value(value), _cached(true), _name(std::move(name)) { set_value(std::move(value)); }
    t_value& operator=(T&& value) {
        set_value(std::move(value));
        return *this;
    }

    ~t_value() {}

    T value(bool usecache = true) const {
        if (usecache && _cached) return _value;
        if (deferred()) {
            try {
                if (false == _future.valid()) {
                    _future = _promise.get_future();
                }
                if (_future.valid()) {
                    _value = _future.get();
                    _cached = true;
                }
            } catch (...) {
            }
        }
        return _value;
    }
    operator T() const { return value(); }
    std::future<T> get_future() {
        if (false == _future.valid()) _future = _promise.get_future();
        return std::move(_future);
    }
    t_value& defer(const std::string& name) {
        _defer = true;
        // reset promise and future for re-binding/lazy evaluation
        _promise = std::promise<T>();
        _future = _promise.get_future();
        _cached = false;
        _name = name;
        return *this;
    }
    bool deferred() const { return _defer; }

    t_value& set_value(const T& value) {
        _value = value;
        _cached = true;
        try {
            _promise.set_value(value);
        } catch (...) {
        }
        return *this;
    }
    t_value& set_value(T&& value) {
        _value = std::move(value);
        _cached = true;
        try {
            _promise.set_value(_value);
        } catch (...) {
        }
        return *this;
    }

    t_value& set_name(const std::string& name) {
        _name = name;
        return *this;
    }
    const std::string& get_name() const { return _name; }

    bool operator<(const t_value& other) const { return this->value() < other.value(); }
    bool operator<=(const t_value& other) const { return this->value() <= other.value(); }
    bool operator>(const t_value& other) const { return this->value() > other.value(); }
    bool operator>=(const t_value& other) const { return this->value() >= other.value(); }
    bool operator==(const t_value& other) const { return this->value() == other.value(); }
    bool operator!=(const t_value& other) const { return this->value() != other.value(); }

   private:
    bool _defer{false};
    mutable T _value = T();
    mutable std::promise<T> _promise;
    mutable std::future<T> _future;
    mutable bool _cached{false};
    std::string _name;
};

}  // namespace hotplace

#endif
