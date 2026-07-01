/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraint_all_except.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTALLEXCEPT__
#define __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTALLEXCEPT__

#include <hotplace/sdk/io/asn.1/constraints/asn1_constraint.hpp>

namespace hotplace {
namespace io {

/**
 */
template <typename T>
class asn1_constraint_all_except : public asn1_constraint_base<T> {
   public:
    asn1_constraint_all_except(asn1_constraint* cons) : asn1_constraint_base<T>(asn1_entity_constraint_all_except), _cons(cons) {
        if (nullptr == cons) {
            // throw exception(errorcode_t::invalid_parameter);
        }
        _cons->set_parent(this);
    }
    virtual ~asn1_constraint_all_except() = default;

    asn1_constraint_all_except* clone() { return new asn1_constraint_all_except<T>(*this); }

    virtual bool is_applicable(asn1_entity_t entity) {
        switch (entity) {
            // TODO
            case asn1_entity_constraint_single:
            case asn1_entity_constraint_size:
            case asn1_entity_constraint_range:
            case asn1_entity_constraint_from:
            case asn1_entity_constraint_pattern:
            case asn1_entity_constraint_including:
            case asn1_entity_constraint_containing:
            default:
                return true;
                break;
        }
    }

    virtual void addref() {
        asn1_constraint_base<T>::addref();
        _cons->addref();
    }
    virtual void release() {
        _cons->release();
        asn1_constraint_base<T>::release();
    }

   protected:
    asn1_constraint_all_except(const asn1_constraint_all_except& other) : asn1_constraint_base<T>(asn1_entity_constraint_all_except) { *this = other; }
    asn1_constraint_all_except& operator=(const asn1_constraint_all_except& other) {
        _cons = other._cons->clone();
        _cons->set_parent(this);
        return *this;
    }

    virtual void represent(stream_t* s, asn1_object* object, asn1_value* value = nullptr) {
        auto rparenthesis = _cons->is_operation();

        s->printf("ALL EXCEPT ");
        if (rparenthesis) s->printf("(");
        _cons->represent(s, object, value);
        if (rparenthesis) s->printf(")");
    }

   private:
    asn1_constraint* _cons;
};

}  // namespace io
}  // namespace hotplace

#endif
