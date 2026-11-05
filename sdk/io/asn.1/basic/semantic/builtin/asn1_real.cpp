/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_real.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/io/asn.1/basic/semantic/builtin/types.hpp>

namespace hotplace {
namespace io {

asn1_real::asn1_real() : asn1_builtin_type(asn1_entity_real) {}

asn1_real::asn1_real(const std::string& name) : asn1_builtin_type(name, asn1_entity_real) {}

asn1_real::asn1_real(const std::string& name, const float& value) : asn1_builtin_type(name, asn1_entity_real, value) {}

asn1_real::asn1_real(const std::string& name, const double& value) : asn1_builtin_type(name, asn1_entity_real, value) {}

asn1_real::~asn1_real() {}

}  // namespace io
}  // namespace hotplace
