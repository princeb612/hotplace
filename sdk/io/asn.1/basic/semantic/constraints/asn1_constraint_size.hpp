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

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_CONSTRAINTS_ASN1CONSTRAINTSIZE__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_CONSTRAINTS_ASN1CONSTRAINTSIZE__

#include <hotplace/sdk/io/asn.1/basic/semantic/constraints/asn1_constraint.hpp>

namespace hotplace {
namespace io {

/**
 * @example
 *          auto cons_size_type1 =
 *              asn1_referenced_type::define("name",
 *                  asn1_builder::build(asn1_entity_ia5string,
 *                              [&](asn1_object* builtin) -> void {
 *                                  builtin->get_constraints().add(
 *                                      new asn1_constraint_size_i(
 *                                          new asn1_constraint_single_value_i(1)));
 *                              }));
 */
template <typename T>
class asn1_constraint_size : public asn1_constraint<T> {
   public:
    asn1_constraint_size(asn1_constraint<T>* cons) : asn1_constraint_size() {
        if (nullptr == cons) {
            throw exception(errorcode_t::not_specified);
        }
        _cons = cons;
        _cons->set_parent(this);
    }
    virtual ~asn1_constraint_size() = default;

    asn1_constraint_size* clone() { return new asn1_constraint_size<T>(*this); }

    virtual bool is_applicable(asn1_entity_t entity) const {
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
        asn1_constraint<T>::addref();
        if (_cons) _cons->addref();
    }
    virtual void release() {
        if (_cons) _cons->release();
        asn1_constraint<T>::release();
    }

   protected:
    asn1_constraint_size() : asn1_constraint<T>(asn1_entity_constraint_size), _cons(nullptr) {}
    asn1_constraint_size(const asn1_constraint_size& other) : asn1_constraint_size() { *this = other; }
    asn1_constraint_size(asn1_constraint_size&& other) : asn1_constraint_size() { *this = std::move(other); }
    asn1_constraint_size& operator=(const asn1_constraint_size& other) {
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
    asn1_constraint_size& operator=(asn1_constraint_size&& other) {
        std::swap(_cons, other._cons);
        return *this;
    }

    virtual void accept(asn1_constraint_evaluator<T>* v) {
        if (_cons) {
            asn1_constraint_evaluator<T> visitor;
            _cons->accept(&visitor);

            auto& result = visitor.get_result_set();
            auto& rs = v->get_result_set();
            rs = std::move(result);
        } else {
            // throw
        }
    }

    virtual void represent(stream_t* s, const asn1_object* object, const asn1_value* value = nullptr) const {
        if (_cons) {
            s->printf("SIZE(");
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
