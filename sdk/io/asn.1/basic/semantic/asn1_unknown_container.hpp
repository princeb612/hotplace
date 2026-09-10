/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_unknown_container.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_ASN1UNKNOWNCONTAINER__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_ASN1UNKNOWNCONTAINER__

#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_type.hpp>
#include <vector>

namespace hotplace {
namespace io {

// sketch - simple and intermediate role
//   asn1_sequence << asn1_unknown_container
class asn1_unknown_container : public asn1_type {
    friend class asn1_container;

   public:
    asn1_unknown_container() : asn1_type(asn1_entity_unknown_container) {}
    ~asn1_unknown_container() { clear(); }

    asn1_unknown_container& operator<<(asn1_object* item) {
        if (item) _container.emplace_back(item);
        return *this;
    }
    void clear() {
        for (auto& item : _container) item->release();
        _container.clear();
    }

   private:
    std::list<asn1_object*> _container;  // splice into asn1_sequence
};

}  // namespace io
}  // namespace hotplace

#endif
