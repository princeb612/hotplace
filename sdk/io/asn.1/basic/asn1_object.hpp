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

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_ASN1OBJECT__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_ASN1OBJECT__

#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/io/asn.1/constraints/asn1_constraints.hpp>
#include <hotplace/sdk/io/asn.1/types.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   ASN.1
 * @remarks
 *          // sketch
 *          asn1_object
 *            asn1_type
 *              asn1_builtin_type
 *                asn1_integer
 *              asn1_tagged_type
 *              asn1_referenced_type
 *              asn1_container
 *                asn1_sequence
 *                asn1_set
 *                asn1_choice
 *              asn1_container_of
 *                asn1_sequence_of
 *                asn1_set_of
 *              asn1_enum
 *          asn1_visitor
 *            asn1_der_visitor
 *            asn1_notation_visitor
 *          asn1_constraint_base
 *            asn1_constraint_single
 *            asn1_constraint_size
 *            asn1_constraint_range
 *            asn1_constraint_from
 *            asn1_constraint_pattern
 */
class asn1_object {
    friend class asn1;
    friend class asn1_tag;
    friend class asn1_type;
    friend class asn1_builtin_type;
    friend class asn1_referenced_type;
    friend class asn1_tagged_type;
    friend class asn1_container;
    friend class asn1_container_of;
    friend class asn1_der_visitor;
    friend class asn1_notation_visitor;

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
    const variant_t& get_default_value() const;
    std::string resolve_name();
    // ComponentType
    int get_componenttype();

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
    bool is_suppressed();

    asn1_object& as_default();
    asn1_object& as_optional();

    asn1_object& as_primitive(bool cascade = true);
    asn1_object& as_constructed(bool cascade = true);

    // suppress identifier octets
    asn1_object& suppress();
    asn1_object& unsuppress();

    asn1_constraints& get_constraints();
    const asn1_constraints& get_constraints() const;

   protected:
    asn1_object(asn1_entity_t entity, const std::string& name = "", asn1_object* object = nullptr, asn1_tag* tag = nullptr);
    asn1_object(const asn1_object& other);
    asn1_object(asn1_object&& other);

    asn1_object& set_entity(asn1_entity_t entity);
    asn1_object& set_default_value(const variant_t& value);
    asn1_object& set_default_value(variant_t&& value);

    virtual void accept(asn1_visitor* v);
    virtual void represent(uint32 depth, stream_t* s, asn1_value* value = nullptr);
    virtual bool represent(uint32 depth, binary_t* b, asn1_value* value = nullptr, uint16 flags = 0);

    virtual void debug_print(uint32 depth);
    virtual void debug_print(uint32 depth, const std::string& name);

   private:
    uint8 _ident;
    std::string _name;
    asn1_entity_t _entity;   //
    uint16 _component_type;  // default, optional
    bool _suppress;

    asn1_object* _parent;  // parent (bottom-up)
    asn1_tag* _tag;        // tagged type
    asn1_object* _object;  // type (top-down)
    variant_t _vt;         // default value

    asn1_constraints _constraints;
    t_shared_reference<asn1_object> _shared;
};

}  // namespace io
}  // namespace hotplace

#endif
