/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraint_intersection.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTINTERSECTION__
#define __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTINTERSECTION__

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
class asn1_constraint_intersection : public asn1_constraint_base<T> {
   public:
    asn1_constraint_intersection(asn1_constraint* lhs, asn1_constraint* rhs) : asn1_constraint_base<T>(asn1_entity_constraint_intersection), _lhs(lhs), _rhs(rhs) {
        if (nullptr == lhs || nullptr == rhs) {
            // throw exception(errorcode_t::invalid_parameter);
        }
        _lhs->set_parent(this);
        _rhs->set_parent(this);
    }

    virtual ~asn1_constraint_intersection() = default;

    asn1_constraint_intersection* clone() { return new asn1_constraint_intersection<T>(*this); }

    virtual bool is_applicable(asn1_entity_t entity) {
        switch (entity) {
            case asn1_entity_constraint_single:
            case asn1_entity_constraint_size:
            case asn1_entity_constraint_range:
            case asn1_entity_constraint_from:
            case asn1_entity_constraint_pattern:
            case asn1_entity_constraint_including:
            case asn1_entity_constraint_containing:
            case asn1_entity_constraint_union:
                return true;
                break;
            default:
                return false;
                break;
        }
    }

    virtual void addref() {
        asn1_constraint_base<T>::addref();
        _lhs->addref();
        _rhs->addref();
    }
    virtual void release() {
        _lhs->release();
        _rhs->release();
        asn1_constraint_base<T>::release();
    }

   protected:
    asn1_constraint_intersection(const asn1_constraint_intersection& other) : asn1_constraint_base<T>(asn1_entity_constraint_intersection) { *this = other; }
    asn1_constraint_intersection& operator=(const asn1_constraint_intersection& other) {
        _lhs = other._lhs->clone();
        _rhs = other._rhs->clone();
        _lhs->set_parent(this);
        _rhs->set_parent(this);
        return *this;
    }

    virtual void represent(stream_t* s, asn1_object* object, asn1_value* value = nullptr) {
        _lhs->represent(s, object, value);
        s->printf(" INTERSECTION ");
        _rhs->represent(s, object, value);
    }

   private:
    asn1_constraint* _lhs;
    asn1_constraint* _rhs;
};

}  // namespace io
}  // namespace hotplace

#endif
