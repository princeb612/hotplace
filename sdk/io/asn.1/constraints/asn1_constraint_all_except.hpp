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
class asn1_constraint_all_except : public asn1_constraint<T> {
   public:
    asn1_constraint_all_except(asn1_constraint<T>* cons) : asn1_constraint_all_except() {
        if (nullptr == cons) {
            // throw exception(errorcode_t::invalid_parameter);
        }
        _cons = cons;
        _cons->set_parent(this);
    }
    virtual ~asn1_constraint_all_except() = default;

    asn1_constraint_all_except* clone() { return new asn1_constraint_all_except<T>(*this); }

    virtual bool is_applicable(asn1_entity_t entity) const {
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
        asn1_constraint<T>::addref();
        if (_cons) _cons->addref();
    }
    virtual void release() {
        if (_cons) _cons->release();
        asn1_constraint<T>::release();
    }

   protected:
    asn1_constraint_all_except() : asn1_constraint<T>(asn1_entity_constraint_all_except), _cons(nullptr) {}
    asn1_constraint_all_except(const asn1_constraint_all_except& other) : asn1_constraint_all_except() { *this = other; }
    asn1_constraint_all_except(asn1_constraint_all_except&& other) : asn1_constraint_all_except() { *this = std::move(other); }
    asn1_constraint_all_except& operator=(const asn1_constraint_all_except& other) {
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
    asn1_constraint_all_except& operator=(asn1_constraint_all_except&& other) {
        std::swap(_cons, other._cons);
        return *this;
    }

    virtual void accept(asn1_constraint_evaluator<T>* v) {
        if (_cons) {
            asn1_constraint_evaluator<T> visitor;
            _cons->accept(&visitor);

            auto& result = visitor.get_result_set().invert();

            auto& rs = v->get_result_set();
            rs = std::move(result);
        } else {
            // throw
        }
    }
    virtual void represent(stream_t* s, const asn1_object* object, const asn1_value* value = nullptr) const {
        if (_cons) {
            auto rparenthesis = _cons->is_operation();

            s->printf("ALL EXCEPT ");
            if (rparenthesis) s->printf("(");
            _cons->represent(s, object, value);
            if (rparenthesis) s->printf(")");
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
