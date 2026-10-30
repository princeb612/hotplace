/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   types.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_PARAMETERIZED_TYPES__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_PARAMETERIZED_TYPES__

#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/types.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   parameterization
 * @remarks
 *          FRAME{TypeParam, INTEGER:maxSize} ::= SEQUENCE {
 *              header  INTEGER,
 *              payload TypeParam,
 *              length  INTEGER (0..maxSize)
 *          }
 *          MyPacket ::= FRAME{ OCTET STRING, 1024 }
 *
 */

enum class asn1_paramtype_t {
    type,
    value,
};
enum class asn1_paramvalue_t {
    entity,
    literal,
    object,
    value,
};

struct HOTPLACE_IO_API asn1_paramtype {
    std::string type;
    std::string name;

    asn1_paramtype(const std::string& t);
    asn1_paramtype(const std::string& t, const std::string& n);

    asn1_paramtype(const asn1_paramtype& other);
    asn1_paramtype(asn1_paramtype&& other);
    asn1_paramtype& operator=(const asn1_paramtype& other);
    asn1_paramtype& operator=(asn1_paramtype&& other);
    bool operator==(const asn1_paramtype& other) const;
    bool operator<(const asn1_paramtype& other) const;

    void represent(stream_t* s, const asn1_value* value) const;
};

struct HOTPLACE_IO_API asn1_paramvalue {
    asn1_paramvalue_t type{asn1_paramvalue_t::entity};
    asn1_entity_t entity{asn1_entity_t::asn1_entity_unknown};
    std::string name;
    asn1_object* object{nullptr};
    variant value;

    asn1_paramvalue();
    asn1_paramvalue(asn1_entity_t e);
    asn1_paramvalue(const char* s);
    asn1_paramvalue(asn1_object* o);
    asn1_paramvalue(const variant& v);
    asn1_paramvalue(variant&& v);

    asn1_paramvalue(const asn1_paramvalue& other);
    asn1_paramvalue(asn1_paramvalue&& other);
    asn1_paramvalue& operator=(const asn1_paramvalue& other);
    asn1_paramvalue& operator=(asn1_paramvalue&& other);

    void represent(stream_t* s, const asn1_value* value) const;
};

typedef std::vector<asn1_paramtype> asn1_paramtypes;
typedef std::vector<asn1_paramvalue> asn1_paramvalues;

}  // namespace io
}  // namespace hotplace

#endif
