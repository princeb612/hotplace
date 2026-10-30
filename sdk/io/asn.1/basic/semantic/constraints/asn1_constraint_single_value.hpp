/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraint_single_value.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_CONSTRAINTS_ASN1CONSTRAINTSINGLEVALUE__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_CONSTRAINTS_ASN1CONSTRAINTSINGLEVALUE__

#include <hotplace/sdk/base/nostd/value.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/constraints/asn1_constraint.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/parameterized/types.hpp>

namespace hotplace {
namespace io {

/**
 * @example
 *          auto cons_single_type1 =
 *              asn1_referenced_type::define("type",
 *                  asn1_builder::build(asn1_entity_integer,
 *                              [&](asn1_object* builtin) -> void {
 *                                  builtin->get_constraints().add(
 *                                      new asn1_constraint_single_value_i(1));
 *                              }));
 */
template <typename T>
class asn1_constraint_single_value : public asn1_constraint<T> {
    friend class asn1_constraint_pattern<T>;

   public:
    asn1_constraint_single_value(const T& value) : asn1_constraint_single_value() { _value = value; }
    asn1_constraint_single_value(T&& value) : asn1_constraint_single_value() { _value = std::move(value); }

    asn1_constraint_single_value(const t_value<T>& value) : asn1_constraint_single_value() { _value = value; }
    asn1_constraint_single_value(t_value<T>&& value) : asn1_constraint_single_value() { _value = std::move(value); }

    virtual ~asn1_constraint_single_value() = default;

    virtual asn1_constraint_single_value* clone() { return new asn1_constraint_single_value(*this); }

    virtual bool is_applicable(asn1_entity_t entity) const { return true; }

   protected:
    asn1_constraint_single_value() : asn1_constraint<T>(asn1_entity_constraint_single), _value(T()) {}
    asn1_constraint_single_value(const asn1_constraint_single_value& other) : asn1_constraint_single_value() { *this = other; }
    asn1_constraint_single_value(asn1_constraint_single_value&& other) : asn1_constraint_single_value() { *this = std::move(other); }
    asn1_constraint_single_value& operator=(const asn1_constraint_single_value& other) {
        asn1_constraint<T>::operator=(other);
        _value = other._value;
        return *this;
    }
    asn1_constraint_single_value& operator=(asn1_constraint_single_value&& other) {
        asn1_constraint<T>::operator=(other);
        _value = std::move(other._value);
        return *this;
    }

    virtual void accept(asn1_constraint_evaluator<T>* v) { v->get_result_set().insert(_value); }

    virtual void represent(stream_t* s, const asn1_object* object, const asn1_value* value = nullptr) const {
        if (_value.deferred()) {
            s->printf("%s", _value.get_name().c_str());
        } else {
            variant vt(_value);
            vtprintf(s, vt, vtprintf_style_t::vtprintf_style_asn1);
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
                            }
                        }
                    }
                };
                lambda(_value);
            }
        }
    }

   private:
    t_value<T> _value;
};

}  // namespace io
}  // namespace hotplace

#endif
