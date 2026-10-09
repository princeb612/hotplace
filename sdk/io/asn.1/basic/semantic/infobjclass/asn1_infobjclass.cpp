/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_infobjclass.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/io/asn.1/basic/semantic/infobjclass/asn1_infobjclass.hpp>

namespace hotplace {
namespace io {

asn1_infobjclass::asn1_infobjclass() {}

asn1_infobjclass::~asn1_infobjclass() {}

void asn1_infobjclass::addref() { _shared.addref(); }

void asn1_infobjclass::release() { _shared.delref(); }

}  // namespace io
}  // namespace hotplace
