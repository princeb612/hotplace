/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_object.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_ASN1OBJECT__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_ASN1OBJECT__

#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/constraints/asn1_constraints.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/types.hpp>

namespace hotplace {
namespace io {

struct asn1_default_t {
    variant_t vt;

    asn1_default_t() {}

    asn1_default_t(const variant_t& v) { vt = v; }
    asn1_default_t(variant_t&& v) { vt = std::move(v); }

    asn1_default_t(const asn1_default_t& other) { vt = other.vt; }
    asn1_default_t(asn1_default_t&& other) { vt = std::move(other.vt); }

    asn1_default_t& operator=(const asn1_default_t& other) {
        vt = other.vt;
        return *this;
    }
    asn1_default_t& operator=(asn1_default_t&& other) {
        vt = std::move(other.vt);
        return *this;
    }
};

/**
 * @brief   ASN.1
 */
class asn1_object {
    friend class asn1_runtime;
    friend class asn1_referenced_type;
    friend class asn1_tagged_type;
    friend class asn1_container;
    friend class asn1_container_of;
    friend class asn1_der_visitor;
    friend class asn1_notation_visitor;
    friend class asn1_weakly_typed;

   public:
    virtual ~asn1_object();

    asn1_object& operator=(const asn1_object& other);
    asn1_object& operator=(asn1_object&& other);

    virtual asn1_object* clone();
    virtual asn1_value* instantiate();
    virtual asn1_object* addref();
    virtual void release();

    void publish(binary_t* b);
    void publish(stream_t* s);

    asn1_object& set_name(const std::string& name);
    asn1_object& set_parent(asn1_object* parent);

    uint8 get_ident() const;
    asn1_object* get_parent() const;
    asn1_object* get_object() const;
    const std::string& get_name() const;
    asn1_entity_t get_entity() const;
    virtual asn1_entity_t get_component_entity() const;  // redefine entity as syntax entity
    uint16 get_component_type() const;
    asn1_tag* get_tag() const;
    variant_t get_default_value() const;
    std::string resolve_name() const;

    // NamedType ::= identifier Type
    bool is_named_type() const;
    // P/C bit 0
    bool is_primitive() const;
    // P/C bit 1
    bool is_constructed() const;
    // TaggedType
    bool is_tagged() const;
    // DEFAULT
    bool is_default() const;
    // IMPLICIT
    bool is_suppressed() const;

    asn1_object& as_default();
    asn1_object& as_optional();

    asn1_object& as_primitive();
    asn1_object& as_constructed();

    // suppress identifier octets
    asn1_object& suppress();
    asn1_object& unsuppress();

    asn1_constraints& get_constraints();
    const asn1_constraints& get_constraints() const;
    virtual bool have_constraints() const;
    bool validate(const asn1_value* value);

   protected:
    asn1_object(asn1_entity_t entity, const std::string& name = "", asn1_object* object = nullptr, asn1_tag* tag = nullptr);
    asn1_object(const asn1_object& other);
    asn1_object(asn1_object&& other);

    asn1_object& set_entity(asn1_entity_t entity);
    asn1_object& set_default_value(const variant_t& value);
    asn1_object& set_default_value(variant_t&& value);
    asn1_object& set_object(asn1_object* object);

    virtual void accept(asn1_visitor* v);
    virtual void accept(asn1_ast_visitor* v);
    virtual void represent(stream_t* s, const asn1_value* value = nullptr) const;
    virtual bool represent(binary_t* b, const asn1_value* value = nullptr, uint16 flags = 0) const;
    bool validate_node(const asn1_object* node, const asn1_value* value);

   private:
    uint8 _ident;
    std::string _name;
    asn1_entity_t _entity;   //
    uint16 _component_type;  // default, optional
    bool _suppress;

    asn1_object* _parent;      // parent (bottom-up)
    asn1_tag* _tag;            // tagged type
    asn1_object* _object;      // type (top-down)
    asn1_default_t* _default;  // default value

    asn1_constraints _constraints;
    t_shared_reference<asn1_object> _shared;
};

}  // namespace io
}  // namespace hotplace

#endif
