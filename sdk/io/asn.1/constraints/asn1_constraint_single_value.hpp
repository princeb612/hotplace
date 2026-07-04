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

#ifndef __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTSINGLEVALUE__
#define __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTSINGLEVALUE__

#include <hotplace/sdk/io/asn.1/constraints/asn1_constraint.hpp>

namespace hotplace {
namespace io {

/**
 * @example
 *          auto type =
 *              asn1_referenced_type::define("type",
 *                  asn1_builtin_type::build(asn1_entity_integer,
 *                              [&](asn1_builtin_type* builtin) -> void {
 *                                  builtin->get_constraints().add(
 *                                          new asn1_constraint_single_value<int>(1));
 *                              }));
 */
template <typename T>
class asn1_constraint_single_value : public asn1_constraint<T> {
   public:
    asn1_constraint_single_value(const T& value) : asn1_constraint_single_value() { _value = value; }
    asn1_constraint_single_value(T&& value) : asn1_constraint_single_value() { _value = std::move(value); }
    virtual ~asn1_constraint_single_value() = default;

    asn1_constraint_single_value* clone() { return new asn1_constraint_single_value(*this); }

    virtual bool is_applicable(asn1_entity_t entity) { return true; }

   protected:
    asn1_constraint_single_value() : asn1_constraint<T>(asn1_entity_constraint_single), _value(_T()) {}
    asn1_constraint_single_value(const asn1_constraint_single_value& other) : asn1_constraint_single_value() { *this = other; }
    asn1_constraint_single_value(asn1_constraint_single_value&& other) : asn1_constraint_single_value() { *this = std::move(other); }
    asn1_constraint_single_value& operator=(const asn1_constraint_single_value& other) {
        _value = other._value;
        return *this;
    }
    asn1_constraint_single_value& operator=(asn1_constraint_single_value&& other) {
        _value = std::move(other._value);
        return *this;
    }

    virtual void accept(asn1_constraint_evaluator<T>* v) { v->get_result_set().insert(_value); }

    virtual void represent(stream_t* s, asn1_object* object, asn1_value* value = nullptr) {
        variant vt(_value);
        vtprintf(s, vt, vtprintf_style_t::vtprintf_style_asn1);
    }

   protected:
   private:
    T _value;
};

}  // namespace io
}  // namespace hotplace

#endif
