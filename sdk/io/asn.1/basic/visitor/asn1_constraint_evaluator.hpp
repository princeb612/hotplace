/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraint_evaluator.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_VISITOR_ASN1CONSTRAINTEVALUATOR__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_VISITOR_ASN1CONSTRAINTEVALUATOR__

#include <hotplace/sdk/base/nostd/set.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/constraints/types.hpp>
#include <hotplace/sdk/io/asn.1/basic/visitor/asn1_constraint_visitor.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   evaluator
 * @sa      asn1_constraints::validate
 * @remarks
 *          auto cons_single_type1 =
 *              asn1_referenced_type::define("Type",
 *                  asn1_builder::build(asn1_entity_integer,
 *                              [&](asn1_object* builtin) -> void {
 *                                  builtin->get_constraints().add(
 *                                      new asn1_constraint_single_value_i(1));
 *                              }));
 *          cons_single_type1->instantiate();
 *          value->set(1);
 *          auto isvalid = cons_single_type1->validate(value);  // call validate -> get_constraints().validate
 *          // do something
 *          cons_single_type1->release();
 */

template <typename T>
class asn1_constraint_evaluator : public asn1_constraint_visitor {
   public:
    virtual ~asn1_constraint_evaluator() = default;

    virtual void visit(const asn1_constraint_t* cons);
    virtual void visit(asn1_constraint<T>* cons);
    t_set_runtime<T>& get_result_set();

   private:
    t_set_runtime<T> _set;
};

template <typename T>
void asn1_constraint_evaluator<T>::visit(const asn1_constraint_t* cons) {
    if (nullptr == cons) return;
    auto cont = (asn1_constraint<T>*)cons;
    if (cont) {
        cont->accept(this);
    }
}

template <typename T>
void asn1_constraint_evaluator<T>::visit(asn1_constraint<T>* cons) {
    if (nullptr == cons) return;
    cons->accept(this);
}

template <typename T>
t_set_runtime<T>& asn1_constraint_evaluator<T>::get_result_set() {
    return _set;
}

}  // namespace io
}  // namespace hotplace

#endif
