/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraint_base.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINT__
#define __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINT__

#include <hotplace/sdk/base/nostd/set.hpp>
#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/constraints/types.hpp>
#include <hotplace/sdk/io/asn.1/types.hpp>

namespace hotplace {
namespace io {

/**
 * ITU-T X.682 ISO/IEC 8824-3
 */
template <typename T>
class asn1_constraint_base : public asn1_constraint {
    friend class asn1_builtin_type;
    friend class asn1_object;

   public:
    virtual ~asn1_constraint_base() = default;

    virtual asn1_constraint_base* clone() { return new asn1_constraint_base(*this); }

    bool is_applicable(asn1_object* object) { return object ? is_applicable(object->get_component_entity()) : false; }
    virtual bool is_applicable(asn1_entity_t entity) { return true; }

    virtual asn1_entity_t get_entity() { return _entity; }
    bool is_operation() override {
        bool ret = false;
        switch (_entity) {
            case asn1_entity_constraint_union:
            case asn1_entity_constraint_intersection:
            case asn1_entity_constraint_except:
            case asn1_entity_constraint_all_except:
                ret = true;
                break;
            default:
                break;
        }
        return ret;
    }
    asn1_constraint* get_parent() override { return _parent; }
    void set_parent(asn1_constraint* parent) override { _parent = parent; }

    t_set_runtime<T>& get_runtime() { return _set; }

    virtual void addref() { _shared.addref(); }
    virtual void release() { _shared.delref(); }

   protected:
    asn1_constraint_base(asn1_entity_t entity) : _entity(entity), _parent(nullptr) { _shared.make_share(this); }

    asn1_constraint_base(const asn1_constraint_base& other) { *this = other; }
    asn1_constraint_base& operator=(const asn1_constraint_base& other) {
        _entity = other._entity;
        return *this;
    }

    virtual void accept(asn1_constraint_visitor* v) { v->visit(this); }
    virtual void represent(stream_t* s, asn1_object* object, asn1_value* value = nullptr) {}

   private:
    asn1_entity_t _entity;
    asn1_constraint* _parent;
    t_set_runtime<T> _set;

    t_shared_reference<asn1_constraint_base> _shared;
};

}  // namespace io
}  // namespace hotplace

#endif
