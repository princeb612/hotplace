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

#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/base/system/shared_instance.hpp>
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

    // ITU-T X.682
    // https://www.oss.com/asn1/resources/asn1-made-simple/advanced-constraints.html

    /**
     * Permitted Alphabet (applicable to strings)
     *   HardToReadChars ::= IA5String (FROM("8BI10OD5S"))
     */
    // asn1_object& constraints_from(const std::string& value);
    /**
     * Pattern (RegEx-like)
     *   LicensePlate ::= IA5String (PATTERN "[0-9]#4(-[A-Z]#2)?") -- NNNN[-NN]
     */
    // asn1_object& constraints_pattern(const std::string& value);
    /**
     * Value Size (applicable to strings, sequence/set of)
     *   LicensePlate ::= IA5String (SIZE (4..7))
     *   CarPark ::= SEQUENCE SIZE (1..25) OF LicensePlate
     */
    // asn1_object& constraints_valuesize(size_t minlen, size_t maxlen);
    /**
     * Value Range (applicable to scalar types)
     *   CarSpeed ::= INTEGER (0..200)
     */
    // asn1_object& constraints_valuerange(size_t minlen, size_t maxlen);
    /**
     * Single Value (applicable to all types)
     *   WarningColors ::= UTF8String ("Red" | "Yellow")
     *   InfoColors ::= UTF8String ("Blue" | "White")
     *   CitySpeedLimit ::= INTEGER (25 | 30 | 40)
     *   HighwaySpeedLimit ::= INTEGER (40 | 50 | 60 | 70)
     */
    // asn1_object& constraints_singlevalue(const std::string& value);
    /**
     * Contained Subtype (applicable to all types)
     *   SignColors ::= UTF8String (InfoColors UNION WarningColors)
     *   SpeedLimitSigns ::= INTEGER (CitySpeedLimit | HighwaySpeedLimit | 10 | 65)
     *   RuralSpeedLimit ::= INTEGER (CitySpeedLimit INTERSECTION HighwaySpeedLimit)
     */
    // asn1_object& constraints_subtype(const std::string& value);
    /**
     * Containing/Encoded By (applicable to octet/bit strings)
     *   PerInside ::= OCTET STRING (
     *                      CONTAINING Doc
     *                      ENCODED BY { joint-iso-itu-t asn1(1)
     *                                   packed-encoding(3)
     *                                   basic(0)
     *                                   unaligned(1)})
     *   pdf OBJECT IDENTIFIER ::= { iso(1)
     *                               member-body(2)
     *                               us(840)
     *                               adobe(113583)
     *                               acrobat(1)}
     *   Doc ::= OCTET STRING (ENCODED BY pdf)
     */
    // asn1_object& constraints_containing(const std::string& value);
    /**
     * WITH COMPONENTS
     */
    // asn1_object& constraints_withcomponents(const std::string& value);

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

   private:
    uint8 _ident;
    std::string _name;
    asn1_entity_t _entity;
    uint16 _component_type;  // default, optional
    bool _suppress;

    asn1_object* _parent;
    asn1_tag* _tag;
    asn1_object* _object;
    variant_t _vt;

    t_shared_reference<asn1_object> _shared;
};

}  // namespace io
}  // namespace hotplace

#endif
