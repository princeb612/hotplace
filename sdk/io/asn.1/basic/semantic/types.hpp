/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   types.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_TYPES__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_TYPES__

#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/io/asn.1/basic/types.hpp>
#include <hotplace/sdk/io/asn.1/runtime/types.hpp>

namespace hotplace {
namespace io {

HOTPLACE_IO_API asn1_entity_t get_entity(const asn1_object* object, bool component = false);
HOTPLACE_IO_API std::string get_entity_name(const asn1_object* object, bool component = false);
HOTPLACE_IO_API std::string nameof(const asn1_object* object);

HOTPLACE_IO_API bool is_kind_of(const asn1_object* object, asn1_entity_t entity);

HOTPLACE_IO_API bool is_kind_of_boolean(const asn1_object* object);
HOTPLACE_IO_API bool is_kind_of_integer(const asn1_object* object);
HOTPLACE_IO_API bool is_kind_of_real(const asn1_object* object);
HOTPLACE_IO_API bool is_kind_of_cstring(const asn1_object* object);
HOTPLACE_IO_API bool is_kind_of_bstring(const asn1_object* object);
HOTPLACE_IO_API bool is_kind_of_container(const asn1_object* object);
HOTPLACE_IO_API bool is_kind_of_container_of(const asn1_object* object);
HOTPLACE_IO_API bool is_default_or_optional(const asn1_object* object);

HOTPLACE_IO_API bool is_kind_of_boolean(asn1_entity_t entity);
HOTPLACE_IO_API bool is_kind_of_integer(asn1_entity_t entity);
HOTPLACE_IO_API bool is_kind_of_real(asn1_entity_t entity);
HOTPLACE_IO_API bool is_kind_of_cstring(asn1_entity_t entity);
HOTPLACE_IO_API bool is_kind_of_bstring(asn1_entity_t entity);
HOTPLACE_IO_API bool is_kind_of_container(asn1_entity_t entity);
HOTPLACE_IO_API bool is_kind_of_container_of(asn1_entity_t entity);

HOTPLACE_IO_API bool evaluate(const asn1_object* obj, const std::string& value);
HOTPLACE_IO_API bool evaluate(const asn1_object* obj, int64 value);

}  // namespace io
}  // namespace hotplace

#endif
