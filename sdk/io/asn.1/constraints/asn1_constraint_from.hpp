/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraint_from.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTFROM__
#define __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTFROM__

#include <hotplace/sdk/io/asn.1/constraints/asn1_constraint.hpp>

namespace hotplace {
namespace io {

/**
 * for each ch
 *     if ch not in alphabet
 *         reject
 */
template <typename T>
class asn1_constraint_from : public asn1_constraint<T> {
   public:
    asn1_constraint_from(asn1_constraint<T>* cons) : asn1_constraint_from() {
        if (nullptr == cons) {
            throw exception(errorcode_t::not_specified);
        }
        _cons = cons;
        _cons->set_parent(this);
    }
    virtual ~asn1_constraint_from() = default;

    asn1_constraint_from* clone() {
        auto entity = asn1_constraint<T>::get_entity();
        switch (entity) {
            // TODO
            case asn1_entity_printstring:
            case asn1_entity_teletexstring:
            case asn1_entity_videotexstring:
            case asn1_entity_ia5string:
            case asn1_entity_graphicstring:
            case asn1_entity_visiblestring:
            case asn1_entity_generalstring:
            case asn1_entity_universalstring:
            case asn1_entity_cstring:
                return true;
                break;
            default:
                return false;
                break;
        }
    }

    virtual bool is_applicable(asn1_entity_t entity);

    virtual void addref() {
        asn1_constraint<T>::addref();
        _cons->addref();
    }
    virtual void release() {
        _cons->release();
        asn1_constraint<T>::release();
    }

   protected:
    asn1_constraint_from() : asn1_constraint<T>(asn1_entity_constraint_size), _cons(nullptr) {}
    asn1_constraint_from(const asn1_constraint_from& other) : asn1_constraint_from() { *this = other; }
    asn1_constraint_from(asn1_constraint_from&& other) : asn1_constraint_from() { *this = std::move(other); }
    asn1_constraint_from& operator=(const asn1_constraint_from& other) {
        if (_cons) {
            _cons->release();
            _cons = nullptr;
        }
        if (other._cons) {
            _cons = other._cons->clone();
            _cons->set_parent(this);
        }
        return *this;
    }
    asn1_constraint_from& operator=(asn1_constraint_from&& other) {
        std::swap(_cons, other._cons);
        if (_cons) _cons->set_parent(this);
        return *this;
    }

    virtual void represent(stream_t* s, asn1_object* object, asn1_value* value = nullptr) {
        if (_cons) {
            s->printf("FROM (");
            _cons->represent(s, object, value);
            s->printf(")");
        } else {
            // throw
        }
    }

   private:
    asn1_constraint<T>* _cons;
};

}  // namespace io
}  // namespace hotplace

#endif
