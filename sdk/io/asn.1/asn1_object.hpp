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

#ifndef __HOTPLACE_SDK_IO_ASN1_ASN1OBJECT__
#define __HOTPLACE_SDK_IO_ASN1_ASN1OBJECT__

#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/io/asn.1/types.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   ASN.1
 * @remarks
 *          // sketch
 *          asn1_object
 *            asn1_named_type
 *            asn1_tag
 *            asn1_type
 *              asn1_builtin_type
 *              asn1_referenced_type
 *              asn1_tagged_type
 *              asn1_container
 *                asn1_sequence
 *                asn1_sequence_of
 *                asn1_set
 *                asn1_set_of
 *                asn1_choice
 *          asn1_visitor
 *            asn1_der_visitor
 *            asn1_notation_visitor
 */
class asn1_object {
    friend class asn1;
    friend class asn1_named_type;
    friend class asn1_tag;
    friend class asn1_type;
    friend class asn1_builtin_type;
    friend class asn1_referenced_type;
    friend class asn1_tagged_type;
    friend class asn1_container;
    friend class asn1_der_visitor;
    friend class asn1_notation_visitor;

   public:
    virtual ~asn1_object();

    asn1_object& operator=(const asn1_object& other);
    asn1_object& operator=(asn1_object&& other);
    asn1_object* clone();
    virtual asn1_value* instantiate();

    void publish(binary_t* b);
    void publish(stream_t* s);

    asn1_object& set_name(const std::string& name);
    asn1_object& set_parent(asn1_object* parent);

    uint8 get_ident() const;
    asn1_object* get_parent() const;
    asn1_object* get_object() const;
    const std::string& get_name() const;
    asn1_entity_t get_entity() const;
    asn1_tag* get_tag() const;

    // ComponentType
    int get_componenttype();
    asn1_object& as_default();
    asn1_object& as_optional();

    asn1_object& as_primitive();
    asn1_object& as_constructed();
    bool is_primitive();
    bool is_constructed();

    bool is_tagged() const;  // nullptr != _tag

    // suppress identifier octets
    asn1_object& suppress();
    asn1_object& unsuppress();
    bool is_suppressed();

    asn1_object* addref();
    void release();

    static asn1_referenced_type* define(const std::string& name, asn1_entity_t entity, asn1_tag* tag = nullptr);
    static asn1_referenced_type* define(const std::string& name, asn1_object* object, asn1_tag* tag = nullptr);

   protected:
    asn1_object(asn1_entity_t entity, const std::string& name = "", asn1_object* object = nullptr, asn1_tag* tag = nullptr);
    asn1_object(const asn1_object& other);
    asn1_object(asn1_object&& other);

    asn1_object& set_entity(asn1_entity_t entity);

    void clear();

    virtual void accept(asn1_visitor* v);
    virtual void represent(uint32 depth, stream_t* s);
    virtual void represent(uint32 depth, binary_t* b, asn1_value* value = nullptr);

   private:
    uint8 _ident;
    std::string _name;
    asn1_entity_t _entity;
    int _component_type;  // default, optional
    bool _suppress;

    asn1_object* _parent;
    asn1_tag* _tag;
    asn1_object* _object;

    t_shared_reference<asn1_object> _shared;
};

}  // namespace io
}  // namespace hotplace

#endif
