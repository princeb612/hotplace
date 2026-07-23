/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_tag.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_ASN1TAG__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_ASN1TAG__

#include <hotplace/sdk/io/asn.1/basic/asn1_object.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   TaggedType
 *          TaggedType ::= Tag Type | Tag IMPLICIT Type | Tag EXPLICIT Type
 *          Tag ::= "[" Class ClassNumber "]"
 */
class asn1_tag : public asn1_object {
    friend class asn1_tagged_type;

   public:
    asn1_tag(uint8 ctype, uint64 cnumber = 0, uint8 tmode = asn1_automatic);
    asn1_tag(const asn1_tag& other);
    virtual ~asn1_tag();

    virtual asn1_tag* clone();
    virtual asn1_tag* addref();

    uint8 get_class() const;
    uint64 get_class_number() const;
    uint8 get_tag_type() const;
    bool is_implicit() const;
    bool is_explicit() const;

    asn1_tag& as_explicit();
    asn1_tag& as_implicit();
    asn1_tag& as_automatic();

   protected:
    virtual void represent(stream_t* s, const asn1_value* value = nullptr) const;
    virtual bool represent(binary_t* b, const asn1_value* value = nullptr, uint16 flags = 0) const;
    void test_and_set_constructed();

   private:
    uint8 _class_type;     // Application
    uint64 _class_number;  // 1
    uint8 _tag_mode;       // implicit
};

}  // namespace io
}  // namespace hotplace

#endif
