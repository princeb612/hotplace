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

namespace hotplace {
namespace io {

asn1_entity_t get_entity(const asn1_object* object, bool component = false);
std::string get_entity_name(const asn1_object* object, bool component = false);
std::string nameof(const asn1_object* object);

bool is_kind_of(const asn1_object* object, asn1_entity_t entity);

bool is_kind_of_integer(const asn1_object* object);
bool is_kind_of_real(const asn1_object* object);
bool is_kind_of_cstring(const asn1_object* object);
bool is_kind_of_bstring(const asn1_object* object);
bool is_kind_of_container(const asn1_object* object);
bool is_kind_of_container_of(const asn1_object* object);

bool is_kind_of_integer(asn1_entity_t entity);
bool is_kind_of_real(asn1_entity_t entity);
bool is_kind_of_cstring(asn1_entity_t entity);
bool is_kind_of_bstring(asn1_entity_t entity);
bool is_kind_of_container(asn1_entity_t entity);
bool is_kind_of_container_of(asn1_entity_t entity);

bool evaluate(const asn1_object* obj, const std::string& value);

return_t print_ast(const asn1_object* object, basic_stream& bs, uint32 flags = asn1_ast_flag_ansicolor);
return_t print_ast(const asn1_runtime* object, basic_stream& bs, uint32 flags = asn1_ast_flag_ansicolor);

}  // namespace io
}  // namespace hotplace

#endif
