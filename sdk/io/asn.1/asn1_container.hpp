/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_ASN1CONTAINER__
#define __HOTPLACE_SDK_IO_ASN1_ASN1CONTAINER__

#include <hotplace/sdk/io/asn.1/asn1_object.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   SequenceType, SequenceOfType, SetType, SetOfType
 */
class asn1_container : public asn1_object {
   public:
    virtual ~asn1_container();

    virtual void represent(stream_t* s);
    virtual void represent(binary_t* b);

    asn1_container& operator<<(asn1_object* rhs);

    void addref();
    void release();

   protected:
    asn1_container(asn1_tag* tag);
    asn1_container(const std::string& name, asn1_tag* tag);
    asn1_container(const asn1_container& rhs);

   private:
    std::list<asn1_object*> _list;
};

}  // namespace io
}  // namespace hotplace

#endif
