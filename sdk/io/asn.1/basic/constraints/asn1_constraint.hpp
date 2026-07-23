/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraint.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_CONSTRAINTS_ASN1CONSTRAINT__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_CONSTRAINTS_ASN1CONSTRAINT__

#include <hotplace/sdk/base/nostd/set.hpp>
#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/basic/constraints/asn1_constraint_evaluator.hpp>
#include <hotplace/sdk/io/asn.1/basic/constraints/asn1_constraint_notation_visitor.hpp>
#include <hotplace/sdk/io/asn.1/basic/constraints/types.hpp>
#include <hotplace/sdk/io/asn.1/types.hpp>

namespace hotplace {
namespace io {

/**
 * ITU-T X.682 ISO/IEC 8824-3
 */
template <typename T>
class asn1_constraint : public asn1_constraint_t {
    friend class asn1_builtin_type;
    friend class asn1_object;
    friend class asn1_constraint_all_except<T>;
    friend class asn1_constraint_except<T>;
    friend class asn1_constraint_from<T>;
    friend class asn1_constraint_intersection<T>;
    friend class asn1_constraint_pattern<T>;
    friend class asn1_constraint_range<T>;
    friend class asn1_constraint_single_value<T>;
    friend class asn1_constraint_size<T>;
    friend class asn1_constraint_union<T>;
    friend class asn1_constraint_evaluator<T>;

   public:
    virtual ~asn1_constraint() = default;

    virtual asn1_constraint* clone() = 0;

    bool is_applicable(asn1_object* object) const { return object ? is_applicable(get_entity(object, true)) : false; }
    virtual bool is_applicable(asn1_entity_t entity) const { return true; }

    asn1_entity_t get_entity() const { return _entity; }
    bool is_operation() const {
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
    asn1_constraint<T>* get_parent() const { return _parent; }
    void set_parent(asn1_constraint<T>* parent) { _parent = parent; }

    virtual void addref() { _shared.addref(); }
    virtual void release() { _shared.delref(); }

   protected:
    asn1_constraint() : _entity(asn1_entity_syntax), _parent(nullptr) { _shared.make_share(this); }
    asn1_constraint(asn1_entity_t entity) : asn1_constraint() { _entity = entity; }

    asn1_constraint(const asn1_constraint& other) : asn1_constraint() { *this = other; }
    asn1_constraint(asn1_constraint&& other) : asn1_constraint() { *this = std::move(other); }
    asn1_constraint& operator=(const asn1_constraint& other) {
        _entity = other._entity;
        _parent = other._parent;
        return *this;
    }
    asn1_constraint& operator=(asn1_constraint&& other) {
        std::swap(_entity, other._entity);
        std::swap(_parent, other._parent);
        return *this;
    }

    virtual void accept(asn1_constraint_visitor* v) { v->visit(this); }
    virtual void accept(asn1_constraint_evaluator<T>* v) { v->visit(this); }
    virtual void represent(stream_t* s, const asn1_object* object, const asn1_value* value = nullptr) const {}

   private:
    asn1_entity_t _entity;
    asn1_constraint<T>* _parent;

    t_shared_reference<asn1_constraint> _shared;
};

}  // namespace io
}  // namespace hotplace

#endif
