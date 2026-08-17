/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_object_class.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_object_class.hpp>

namespace hotplace {
namespace io {

asn1_object_class::asn1_object_class() {}

asn1_object_class::~asn1_object_class() {}

void asn1_object_class::addref() { _shared.addref(); }

void asn1_object_class::release() { _shared.delref(); }

}  // namespace io
}  // namespace hotplace
