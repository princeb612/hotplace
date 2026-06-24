/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_type.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/io/asn.1/basic/asn1_type.hpp>

namespace hotplace {
namespace io {

asn1_type::asn1_type(asn1_entity_t entity, const std::string& name, asn1_object* object, asn1_tag* tag) : asn1_object(entity, name, object, tag) {}

asn1_type::~asn1_type() {}

}  // namespace io
}  // namespace hotplace
