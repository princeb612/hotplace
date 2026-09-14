/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   set.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2026.07.01   Soo Han and Gemini  redesign
 *
 */

#ifndef __HOTPLACE_SDK_BASE_NOSTD_SET__
#define __HOTPLACE_SDK_BASE_NOSTD_SET__

#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/base/nostd/range_set.hpp>
#include <hotplace/sdk/base/nostd/string_set.hpp>
#include <hotplace/sdk/base/nostd/traits.hpp>
#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <memory>

namespace hotplace {

/*
 * concrete_set_t
 *   if is_same<T, std::string> string_set
 *   else t_range_set<t_range_value<T>>
 *
 * t_set_runtime::concrete_set_t is t_interval<t_range_value<int>>
 *   .insert_range(range_type_t::minvalue, 0)                              // [MIN, 0]
 *   .insert_range(1, 2)                                                   // [1, 2]
 *   .insert_range(interval(3, 5, range_flag_t::open, range_flag_t::open)  // (3, 5)
 */
template <typename T,                                                                                 //
          typename std::enable_if<custom::is_integral<typename std::decay<T>::type>::value ||         //
                                      std::is_floating_point<typename std::decay<T>::type>::value ||  //
                                      std::is_same<T, std::string>::value,
                                  int>::type = 0>
class t_set_runtime {
   public:
    using decayed_t = typename std::decay<T>::type;
    using concrete_set_t = typename std::conditional<std::is_same<decayed_t, std::string>::value, string_set, t_range_set<t_range_value<decayed_t>>>::type;

    t_set_runtime() {
        _shared.make_share(this);
        _target.reset(new concrete_set_t());
    }
    t_set_runtime(const t_set_runtime<T>& other) : t_set_runtime() { *this = other; }
    t_set_runtime(t_set_runtime<T>&& other) : t_set_runtime() { *this = std::move(other); }
    t_set_runtime& operator=(const t_set_runtime<T>& other) {
        _target->operator=(*other._target);
        return *this;
    }
    t_set_runtime& operator=(t_set_runtime<T>&& other) {
        auto inst = _target.get();
        *inst = std::move(*other._target);
        return *this;
    }

    template <typename U = decayed_t, typename std::enable_if<custom::is_integral<U>::value, int>::type = 0>
    type_category_t type() const {
        return type_category_t::integral;
    }
    template <typename U = decayed_t, typename std::enable_if<std::is_floating_point<U>::value, int>::type = 0>
    type_category_t type() const {
        return type_category_t::real;
    }
    template <typename U = decayed_t, typename std::enable_if<std::is_same<U, std::string>::value, int>::type = 0>
    type_category_t type() const {
        return type_category_t::literal;
    }

    t_set_runtime& reset() {
        _target->reset();
        return *this;
    }
    t_set_runtime& insert(const decayed_t& value) {
        _target->insert(value);
        return *this;
    }
    t_set_runtime& erase(const decayed_t& value) {
        _target->erase(value);
        return *this;
    }
    bool contains(const decayed_t& value) const { return _target->contains(value); }

    template <typename U = decayed_t>
    typename std::enable_if<std::is_same<U, std::string>::value, bool>::type  //
    from(const decayed_t& value) {
        return _target->from(value);
    }

    template <typename U = decayed_t>
    typename std::enable_if<std::is_same<U, std::string>::value, bool>::type  //
    regex(const decayed_t& value) {
        return _target->regex(value);
    }

    template <typename U = decayed_t>
    typename std::enable_if<custom::is_integral<U>::value || std::is_floating_point<U>::value, bool>::type  //
    contains(const t_range_value<U>& value) {
        return _target->contains(value);
    }

    // 1) primitive types and types allowing implicit conversion (including std::string)
    template <typename U = decayed_t>
    typename std::enable_if<custom::is_integral<U>::value || std::is_floating_point<U>::value || std::is_same<U, std::string>::value, t_set_runtime&>::type  //
    insert_range(const U& start, const U& end, range_flag_t sflag = range_flag_t::closed, range_flag_t eflag = range_flag_t::closed) {
        _target->insert_range(static_cast<T>(start), static_cast<T>(end), sflag, eflag);
        return *this;
    }

    template <typename U = decayed_t>
    typename std::enable_if<custom::is_integral<U>::value || std::is_floating_point<U>::value || std::is_same<U, std::string>::value, t_set_runtime&>::type  //
    erase_range(const U& start, const U& end, range_flag_t sflag = range_flag_t::closed, range_flag_t eflag = range_flag_t::closed) {
        _target->erase_range(static_cast<T>(start), static_cast<T>(end), sflag, eflag);
        return *this;
    }

    // 2) when passed directly in the form of t_range_value<U> (when specifying MIN and MAX)
    template <typename U = decayed_t>
    typename std::enable_if<custom::is_integral<U>::value || std::is_floating_point<U>::value, t_set_runtime&>::type  //
    insert_range(const t_range_value<U>& start, const t_range_value<U>& end, range_flag_t sflag = range_flag_t::closed, range_flag_t eflag = range_flag_t::closed) {
        _target->insert_range(start, end, sflag, eflag);
        return *this;
    }

    template <typename U = decayed_t>
    typename std::enable_if<custom::is_integral<U>::value || std::is_floating_point<U>::value, t_set_runtime&>::type  //
    erase_range(const t_range_value<U>& start, const t_range_value<U>& end, range_flag_t sflag = range_flag_t::closed, range_flag_t eflag = range_flag_t::closed) {
        _target->erase_range(start, end, sflag, eflag);
        return *this;
    }

    // 3) when passed directly in the form of t_interval<t_range_value<U>>
    template <typename U = decayed_t>
    typename std::enable_if<custom::is_integral<U>::value || std::is_floating_point<U>::value, t_set_runtime&>::type  //
    insert_range(const t_interval<t_range_value<U>>& interval) {
        _target->insert_range(interval);
        return *this;
    }

    template <typename U = decayed_t>
    typename std::enable_if<custom::is_integral<U>::value || std::is_floating_point<U>::value, t_set_runtime&>::type  //
    erase_range(const t_interval<t_range_value<U>>& interval) {
        _target->erase_range(interval);
        return *this;
    }

    t_set_runtime& union_with(const t_set_runtime<T>& other) {
        _target->union_with(*other._target);
        return *this;
    }
    t_set_runtime& erase_from(const t_set_runtime<T>& other) {
        _target->erase_from(*other._target);
        return *this;
    }
    t_set_runtime& intersect_with(const t_set_runtime<T>& other) {
        _target->intersect_with(*other._target);
        return *this;
    }
    t_set_runtime& contains_all(const t_set_runtime<T>& other) const { return _target->contains_all(*other._target); }

    /* ALL EXCEPT */
    t_set_runtime& invert() {
        _target->invert();
        return *this;
    }
    bool is_inverted() const { return _target->is_inverted(); }

    bool operator==(const t_set_runtime& other) { return _target->operator==(*other._target); }
    bool operator!=(const t_set_runtime& other) { return (false == (*this == other)); }

    void addref() { _shared.addref(); }
    void release() { _shared.delref(); }

   protected:
   private:
    std::unique_ptr<concrete_set_t> _target;
    t_shared_reference<t_set_runtime<T>> _shared;
};

}  // namespace hotplace

#endif
