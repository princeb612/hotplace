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

#ifndef __HOTPLACE_SDK_IO_ASN1_ASN1TAG__
#define __HOTPLACE_SDK_IO_ASN1_ASN1TAG__

#include <sdk/io/asn.1/asn1_object.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   TaggedType
 *          TaggedType ::= Tag Type | Tag IMPLICIT Type | Tag EXPLICIT Type
 *          Tag ::= "[" Class ClassNumber "]"
 */
class asn1_tag : public asn1_object {
   public:
    asn1_tag(int cnumber, asn1_tag* tag = nullptr);
    asn1_tag(int cnumber, int tmode, asn1_tag* tag = nullptr);
    asn1_tag(int ctype, int cnumber, int tmode, asn1_tag* tag = nullptr);
    asn1_tag(const asn1_tag& rhs);

    virtual asn1_object* clone();

    virtual void represent(stream_t* s);
    virtual void represent(binary_t* b);

    int get_class() const;
    int get_class_number() const;
    int get_tag_type() const;
    bool is_implicit() const;
    void suppress();
    void unsuppress();

   protected:
    bool is_suppressed() const;

   private:
    int _class_type;    // Application
    int _class_number;  // 1
    int _tag_mode;      // implicit
    bool _suppress;
};

}  // namespace io
}  // namespace hotplace

#endif
