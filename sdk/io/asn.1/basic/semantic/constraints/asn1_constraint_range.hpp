/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraint_range.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_CONSTRAINTS_ASN1CONSTRAINTRANGE__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_CONSTRAINTS_ASN1CONSTRAINTRANGE__

#include <hotplace/sdk/base/nostd/range_set.hpp>
#include <hotplace/sdk/base/stream/vtprintf.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/constraints/asn1_constraint.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/parameterized/asn1_specialized_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/parameterized/types.hpp>

namespace hotplace {
namespace io {

/**
 * @example
 *          auto cons_range_type1 =
 *              asn1_referenced_type::define("type",
 *                  asn1_builder::build(asn1_entity_integer,
 *                              [&](asn1_object* builtin) -> void {
 *                                  builtin->get_constraints().add(
 *                                      new asn1_constraint_union_i(
 *                                          new asn1_constraint_range_i(1, 10),
 *                                          new asn1_constraint_range_i(20, 30)));
 *                              }));
 */
template <typename T>
class asn1_constraint_range : public asn1_constraint<T> {
   public:
    using decayed_t = typename std::decay<T>::type;

    template <typename U = decayed_t,  //
              typename std::enable_if<custom::is_integral<U>::value || std::is_floating_point<U>::value, int>::type = 0>
    asn1_constraint_range(const U& low, const U& high, range_flag_t low_flag = range_flag_t::closed, range_flag_t high_flag = range_flag_t::closed)
        : asn1_constraint_range() {
        _low = t_range_value<U>(low);
        _high = t_range_value<U>(high);
        _low_flag = low_flag;
        _high_flag = high_flag;
    }

    template <typename U = decayed_t,  //
              typename std::enable_if<std::is_same<U, std::string>::value, int>::type = 0>
    asn1_constraint_range(const U& low, const U& high, range_flag_t low_flag = range_flag_t::closed, range_flag_t high_flag = range_flag_t::closed)
        : asn1_constraint_range() {
        _low = low;
        _high = high;
        _low_flag = low_flag;
        _high_flag = high_flag;
    }

    template <typename U = decayed_t,  //
              typename std::enable_if<custom::is_integral<U>::value || std::is_floating_point<U>::value, int>::type = 0>
    asn1_constraint_range(range_type_t low_type, const U& high, range_flag_t low_flag = range_flag_t::closed, range_flag_t high_flag = range_flag_t::closed)
        : asn1_constraint_range() {
        _low = t_range_value<U>(low_type);
        _high = t_range_value<U>(high);
        _low_flag = low_flag;
        _high_flag = high_flag;
    }

    template <typename U = decayed_t,  //
              typename std::enable_if<custom::is_integral<U>::value || std::is_floating_point<U>::value, int>::type = 0>
    asn1_constraint_range(const U& low, range_type_t high_type, range_flag_t low_flag = range_flag_t::closed, range_flag_t high_flag = range_flag_t::closed)
        : asn1_constraint_range() {
        _low = t_range_value<U>(low);
        _high = t_range_value<U>(high_type);
        _low_flag = low_flag;
        _high_flag = high_flag;
    }

    template <typename U = decayed_t,  //
              typename std::enable_if<custom::is_integral<U>::value || std::is_floating_point<U>::value, int>::type = 0>
    asn1_constraint_range(range_type_t low_type, range_type_t high_type, range_flag_t low_flag = range_flag_t::closed, range_flag_t high_flag = range_flag_t::closed)
        : asn1_constraint_range() {
        _low = t_range_value<U>(low_type);
        _high = t_range_value<U>(high_type);
        _low_flag = low_flag;
        _high_flag = high_flag;
    }

    template <typename U = decayed_t,  //
              typename std::enable_if<custom::is_integral<U>::value || std::is_floating_point<U>::value, int>::type = 0>
    asn1_constraint_range(const t_value<U>& low, const t_value<U>& high, range_flag_t low_flag = range_flag_t::closed, range_flag_t high_flag = range_flag_t::closed)
        : asn1_constraint_range() {
        _low.value = low;
        _high.value = high;
        _low_flag = low_flag;
        _high_flag = high_flag;
    }

    template <typename U = decayed_t,  //
              typename std::enable_if<custom::is_integral<U>::value || std::is_floating_point<U>::value, int>::type = 0>
    asn1_constraint_range(const t_value<U>& low, const U& high, range_flag_t low_flag = range_flag_t::closed, range_flag_t high_flag = range_flag_t::closed)
        : asn1_constraint_range() {
        _low.value = low;
        _high = t_range_value<U>(high);
        _low_flag = low_flag;
        _high_flag = high_flag;
    }

    template <typename U = decayed_t,  //
              typename std::enable_if<custom::is_integral<U>::value || std::is_floating_point<U>::value, int>::type = 0>
    asn1_constraint_range(const U& low, const t_value<U>& high, range_flag_t low_flag = range_flag_t::closed, range_flag_t high_flag = range_flag_t::closed)
        : asn1_constraint_range() {
        _low = t_range_value<U>(low);
        _high.value = high;
        _low_flag = low_flag;
        _high_flag = high_flag;
    }

    template <typename U = decayed_t,  //
              typename std::enable_if<custom::is_integral<U>::value || std::is_floating_point<U>::value, int>::type = 0>
    asn1_constraint_range(range_type_t low_type, const t_value<U>& high, range_flag_t low_flag = range_flag_t::closed, range_flag_t high_flag = range_flag_t::closed)
        : asn1_constraint_range() {
        _low = t_range_value<U>(low_type);
        _high.value = high;
        _low_flag = low_flag;
        _high_flag = high_flag;
    }

    template <typename U = decayed_t,  //
              typename std::enable_if<custom::is_integral<U>::value || std::is_floating_point<U>::value, int>::type = 0>
    asn1_constraint_range(const t_value<U>& low, range_type_t high_type, range_flag_t low_flag = range_flag_t::closed, range_flag_t high_flag = range_flag_t::closed)
        : asn1_constraint_range() {
        _low.value = low;
        _high = t_range_value<U>(high_type);
        _low_flag = low_flag;
        _high_flag = high_flag;
    }

    template <typename U = decayed_t,  //
              typename std::enable_if<std::is_same<U, std::string>::value, int>::type = 0>
    asn1_constraint_range(const t_value<U>& low, const t_value<U>& high, range_flag_t low_flag = range_flag_t::closed, range_flag_t high_flag = range_flag_t::closed)
        : asn1_constraint_range() {
        _low.value = low;
        _high.value = high;
        _low_flag = low_flag;
        _high_flag = high_flag;
    }

    template <typename U = decayed_t,  //
              typename std::enable_if<std::is_same<U, std::string>::value, int>::type = 0>
    asn1_constraint_range(const t_value<U>& low, const U& high, range_flag_t low_flag = range_flag_t::closed, range_flag_t high_flag = range_flag_t::closed)
        : asn1_constraint_range() {
        _low.value = low;
        _high = high;
        _low_flag = low_flag;
        _high_flag = high_flag;
    }

    template <typename U = decayed_t,  //
              typename std::enable_if<std::is_same<U, std::string>::value, int>::type = 0>
    asn1_constraint_range(const U& low, const t_value<U>& high, range_flag_t low_flag = range_flag_t::closed, range_flag_t high_flag = range_flag_t::closed)
        : asn1_constraint_range() {
        _low = low;
        _high.value = high;
        _low_flag = low_flag;
        _high_flag = high_flag;
    }

    virtual ~asn1_constraint_range() = default;

    virtual asn1_constraint_range* clone() { return new asn1_constraint_range<T>(*this); }

    virtual bool is_applicable(asn1_entity_t entity) const {
        switch (entity) {
            case asn1_entity_integer:
            case asn1_entity_real:
                return true;
                break;
            default:
                return false;
                break;
        }
    }

   protected:
    asn1_constraint_range()
        : asn1_constraint<T>(asn1_entity_constraint_range), _low(T()), _high(T()), _low_flag(range_flag_t::closed), _high_flag(range_flag_t::closed) {}
    asn1_constraint_range(const asn1_constraint_range& other) : asn1_constraint_range() { *this = other; }
    asn1_constraint_range(asn1_constraint_range&& other) : asn1_constraint_range() { *this = std::move(other); }
    asn1_constraint_range& operator=(const asn1_constraint_range& other) {
        asn1_constraint<T>::operator=(other);
        _low = other._low;
        _high = other._high;
        _low_flag = other._low_flag;
        _high_flag = other._high_flag;
        return *this;
    }
    asn1_constraint_range& operator=(asn1_constraint_range&& other) {
        asn1_constraint<T>::operator=(other);
        _low = std::move(other._low);
        _high = std::move(other._high);
        std::swap(_low_flag, other._low_flag);
        std::swap(_high_flag, other._high_flag);
        return *this;
    }

    virtual void accept(asn1_constraint_evaluator<T>* v) { do_accept(v); }

    template <typename U = decayed_t,  //
              typename std::enable_if<custom::is_integral<U>::value || std::is_floating_point<U>::value, int>::type = 0>
    void do_accept(asn1_constraint_evaluator<T>* v) {
        v->get_result_set().insert_range(_low, _high, _low_flag, _high_flag);
    }

    template <typename U = decayed_t,  //
              typename std::enable_if<std::is_same<U, std::string>::value, int>::type = 0>
    void do_accept(asn1_constraint_evaluator<T>* v) {
        v->get_result_set().insert_range(_low.value.value(), _high.value.value(), _low_flag, _high_flag);
    }

    virtual void represent(stream_t* s, const asn1_object* object, const asn1_value* value = nullptr) const {
        switch (_low.type) {
            case range_type_t::minvalue:
                s->printf("MIN");
                break;
            case range_type_t::value: {
                if (_low.value.is_named()) {
                    s->printf("%s", _low.value.get_name().c_str());
                } else {
                    variant vt(_low.value);
                    vtprintf(s, vt, vtprintf_style_t::vtprintf_style_asn1);
                }
            } break;
            case range_type_t::maxvalue:
                s->printf("MAX");
                break;
        }
        if (range_flag_t::open == _low_flag) s->printf("<");
        if ((_low != _high) || _high.value.is_named()) {
            s->printf("..");
            if (range_flag_t::open == _high_flag) s->printf("<");
            switch (_high.type) {
                case range_type_t::minvalue:
                    s->printf("MIN");
                    break;
                case range_type_t::value: {
                    if (_high.value.is_named()) {
                        s->printf("%s", _high.value.get_name().c_str());
                    } else {
                        variant vt(_high.value);
                        vtprintf(s, vt, vtprintf_style_t::vtprintf_style_asn1);
                    }
                } break;
                case range_type_t::maxvalue:
                    s->printf("MAX");
                    break;
            }
        }
    }

    virtual void update(asn1_object* owner) {
        if (owner) {
            auto root = owner->get_root();
            if (is_kind_of(root, asn1_entity_specialized_type)) {
                auto spec = (asn1_specialized_type*)root;
                auto lambda = [&](t_value<T>& v) -> void {
                    const auto& name = v.get_name();
                    if (false == name.empty()) {
                        asn1_paramvalue pv;
                        auto test = spec->lookup_value(name, pv);
                        if (test) {
                            switch (this->type()) {
                                case type_category_t::integral: {
                                    if ((asn1_paramvalue_t::value == pv.type) && (pv.value.is_int())) {
                                        v.set_value(pv.value.as<T>());
                                    }
                                } break;
                                case type_category_t::real: {
                                    if ((asn1_paramvalue_t::value == pv.type) && (pv.value.is_float())) {
                                        v.set_value(pv.value.as<T>());
                                    }
                                } break;
                                case type_category_t::literal: {
                                    if ((asn1_paramvalue_t::value == pv.type) && (pv.value.is_string())) {
                                        v.set_value(pv.value.as<T>());
                                    }
                                } break;
                                default:
                                    break;
                            }
                        }
                    }
                };
                lambda(_low.value);
                lambda(_high.value);
            }
        }
    }

   private:
    t_range_value<T> _low;
    t_range_value<T> _high;
    range_flag_t _low_flag;
    range_flag_t _high_flag;
};

}  // namespace io
}  // namespace hotplace

#endif
