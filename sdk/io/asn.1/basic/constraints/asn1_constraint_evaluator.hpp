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

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_CONSTRAINTS_ASN1CONSTRAINTEVALUATOR__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_CONSTRAINTS_ASN1CONSTRAINTEVALUATOR__

#include <hotplace/sdk/base/nostd/set.hpp>
#include <hotplace/sdk/io/asn.1/basic/constraints/asn1_constraint_visitor.hpp>
#include <hotplace/sdk/io/asn.1/basic/constraints/types.hpp>

namespace hotplace {
namespace io {

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
