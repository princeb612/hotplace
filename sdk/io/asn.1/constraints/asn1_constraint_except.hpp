/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraint_except.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTEXCEPT__
#define __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTEXCEPT__

#include <hotplace/sdk/io/asn.1/constraints/asn1_constraint.hpp>

namespace hotplace {
namespace io {

/**
 */
template <typename T>
class asn1_constraint_except : public asn1_constraint_base<T> {
   public:
    asn1_constraint_except(asn1_constraint* lhs, asn1_constraint* rhs) : asn1_constraint_base<T>(asn1_entity_constraint_except), _lhs(lhs), _rhs(rhs) {
        if (nullptr == lhs || nullptr == rhs) {
            // throw exception(errorcode_t::invalid_parameter);
        }
        _lhs->set_parent(this);
        _rhs->set_parent(this);
    }
    virtual ~asn1_constraint_except() = default;

    asn1_constraint_except* clone() { return new asn1_constraint_except<T>(*this); }

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
    asn1_constraint_except(const asn1_constraint_except& other) : asn1_constraint_base<T>(asn1_entity_constraint_except) { *this = other; }
    asn1_constraint_except& operator=(const asn1_constraint_except& other) {
        _lhs = other._lhs->clone();
        _rhs = other._rhs->clone();
        _lhs->set_parent(this);
        _rhs->set_parent(this);
        return *this;
    }

    virtual void represent(stream_t* s, asn1_object* object, asn1_value* value = nullptr) {
        auto lparenthesis = _lhs->is_operation();
        auto rparenthesis = _rhs->is_operation();

        if (lparenthesis) s->printf("(");
        _lhs->represent(s, object, value);
        if (lparenthesis) s->printf(")");
        s->printf(" EXCEPT ");
        if (rparenthesis) s->printf("(");
        _rhs->represent(s, object, value);
        if (rparenthesis) s->printf(")");
    }

   private:
    asn1_constraint* _lhs;
    asn1_constraint* _rhs;
};

}  // namespace io
}  // namespace hotplace

#endif
