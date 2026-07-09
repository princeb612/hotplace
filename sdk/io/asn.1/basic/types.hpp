/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   types.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_TYPES__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_TYPES__

#include <hotplace/sdk/io/asn.1/types.hpp>

namespace hotplace {
namespace io {

asn1_entity_t get_entity(asn1_object* object, bool component = false);
std::string nameof(asn1_object* object);

bool is_kind_of(asn1_object* object, asn1_entity_t entity);

bool is_kind_of_integer(asn1_object* object);
bool is_kind_of_real(asn1_object* object);
bool is_kind_of_cstring(asn1_object* object);
bool is_kind_of_bstring(asn1_object* object);
bool is_kind_of_container(asn1_object* object);
bool is_kind_of_container_of(asn1_object* object);

bool is_kind_of_integer(asn1_entity_t entity);
bool is_kind_of_real(asn1_entity_t entity);
bool is_kind_of_cstring(asn1_entity_t entity);
bool is_kind_of_bstring(asn1_entity_t entity);
bool is_kind_of_container(asn1_entity_t entity);
bool is_kind_of_container_of(asn1_entity_t entity);

bool evaluate(asn1_object* obj, const std::string& value);

}  // namespace io
}  // namespace hotplace

#endif
