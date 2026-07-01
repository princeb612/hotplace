/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraint_size.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTSIZE__
#define __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTSIZE__

#include <hotplace/sdk/base/nostd/range.hpp>
#include <hotplace/sdk/io/asn.1/constraints/asn1_constraint.hpp>

namespace hotplace {
namespace io {

template <typename T>
class asn1_constraint_size : public asn1_constraint_base<T> {
   public:
    asn1_constraint_size(asn1_constraint* cons) : asn1_constraint_base<T>(asn1_entity_constraint_size), _cons(cons) {
        if (nullptr == cons) {
            throw exception(errorcode_t::not_specified);
        }
    }
    virtual ~asn1_constraint_size() = default;

    asn1_constraint_size* clone() { return new asn1_constraint_size<T>(*this); }

    virtual bool is_applicable(asn1_entity_t entity) {
        switch (entity) {
            case asn1_entity_bitstring:
            case asn1_entity_octstring:
            case asn1_entity_cstring:
            case asn1_entity_sequence_of:
            case asn1_entity_set_of:
                return true;
                break;
            default:
                return false;
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
    asn1_constraint_size(const asn1_constraint_size& other) : asn1_constraint_base<T>(asn1_entity_constraint_size) { *this = other; }
    asn1_constraint_size& operator=(const asn1_constraint_size& other) {
        _cons = other._cons->clone();
        return *this;
    }

    virtual void represent(stream_t* s, asn1_object* object, asn1_value* value = nullptr) {
        s->printf("SIZE(");
        _cons->represent(s, object, value);
        s->printf(")");
    }

   private:
    asn1_constraint* _cons;
};

}  // namespace io
}  // namespace hotplace

#endif
