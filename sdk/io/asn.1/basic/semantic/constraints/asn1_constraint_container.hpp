/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraint_container.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_CONSTRAINTS_ASN1CONSTRAINTCONTAINER__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_CONSTRAINTS_ASN1CONSTRAINTCONTAINER__

#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/constraints/types.hpp>

namespace hotplace {
namespace io {

/**
 * dedicated container cf. ("SubtypeElementSet", {"SubtypeElementSet", "SubtypeElement"})
 */
class asn1_constraint_container : public asn1_constraint_t {
    friend class asn1_constraints;

   public:
    asn1_constraint_container() { _shared.make_share(this); }
    virtual ~asn1_constraint_container() { clear(); }

    asn1_constraint_container(const asn1_constraint_container& other) : asn1_constraint_container() { *this = other; }
    asn1_constraint_container& operator=(const asn1_constraint_container& other) {
        _list = other._list;
        return *this;
    }

    asn1_constraint_container* clone() { return new asn1_constraint_container(*this); }

    virtual asn1_entity_t get_entity() const { return asn1_entity_constraint_container; }
    virtual bool is_operation() const { return true; }

    virtual void accept(asn1_constraint_visitor* v) {}
    virtual void represent(stream_t* s, const asn1_object* object, const asn1_value* value = nullptr) const {}

    virtual type_category_t type() const { return type_category_t::unknown; }

    asn1_constraint_container& add(asn1_constraint_t* item) {
        if (item) {
            if (asn1_entity_constraint_container != item->get_entity()) _list.emplace_back(item);
        }
        return *this;
    }

    void clear() {
        for (auto& item : _list) item->release();
        _list.clear();
    }

    virtual void addref() { _shared.addref(); }
    virtual void release() { _shared.delref(); }

   private:
    std::list<asn1_constraint_t*> _list;
    t_shared_reference<asn1_constraint_container> _shared;
};

}  // namespace io
}  // namespace hotplace

#endif
