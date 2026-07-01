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

#ifndef __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTRANGE__
#define __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTRANGE__

#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/base/nostd/range_set.hpp>
#include <hotplace/sdk/io/asn.1/constraints/asn1_constraint.hpp>

namespace hotplace {
namespace io {

/**
 * @example
 *          auto type =
 *              asn1_referenced_type::define("type",
 *                  asn1_builder::build(asn1_entity_integer,
 *                              [&](asn1_builtin_type* builtin) -> void {
 *                                  builtin->get_constraints().add(
 *                                          new asn1_constraint_intersection<int>(
 *                                              new asn1_constraint_range<int>(1, 100),
 *                                              new asn1_constraint_range<int>(50, 200)));
 *                              }));
 */
template <typename T>
class asn1_constraint_range : public asn1_constraint_base<T> {
   public:
    asn1_constraint_range(t_range_value<T> low, t_range_value<T> high) : asn1_constraint_base<T>(asn1_entity_constraint_range), _low(low), _high(high) {}
    virtual ~asn1_constraint_range() = default;

    asn1_constraint_range* clone() { return new asn1_constraint_range<T>(*this); }

    virtual bool is_applicable(asn1_entity_t entity) {
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
    asn1_constraint_range(const asn1_constraint_range& other) : asn1_constraint_base<T>(asn1_entity_constraint_range) {
        _low = other._low;
        _high = other._high;
    }
    asn1_constraint_range& operator=(const asn1_constraint_range& other) {
        _low = other._low;
        _high = other._high;
        return *this;
    }

    virtual void represent(stream_t* s, asn1_object* object, asn1_value* value = nullptr) {
        auto parenthesis = false;
        auto parent = asn1_constraint_base<T>::get_parent();
        if (parent) {
            auto entity = parent->get_entity();
            switch (entity) {
                case asn1_entity_constraint_intersection:
                    parenthesis = true;
                    break;
                default:
                    break;
            }
        }

        if (parenthesis) {
            s->printf("(");
        }
        switch (_low.type) {
            case range_type_t::minvalue:
                s->printf("MIN");
                break;
            case range_type_t::value: {
                variant vt(_low.value);
                vtprintf(s, vt, vtprintf_style_t::vtprintf_style_asn1);
            } break;
            case range_type_t::maxvalue:
                s->printf("MAX");
                break;
        }
        if (_low != _high) {
            s->printf("..");
            switch (_high.type) {
                case range_type_t::minvalue:
                    s->printf("MIN");
                    break;
                case range_type_t::value: {
                    variant vt(_high.value);
                    vtprintf(s, vt, vtprintf_style_t::vtprintf_style_asn1);
                } break;
                case range_type_t::maxvalue:
                    s->printf("MAX");
                    break;
            }
        }
        if (parenthesis) {
            s->printf(")");
        }
    }

   private:
    t_range_value<T> _low;
    t_range_value<T> _high;
};

}  // namespace io
}  // namespace hotplace

#endif
