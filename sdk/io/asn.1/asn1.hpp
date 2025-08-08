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

#ifndef __HOTPLACE_SDK_IO_ASN1_ASN1__
#define __HOTPLACE_SDK_IO_ASN1_ASN1__

#include <sdk/base/system/shared_instance.hpp>
#include <sdk/io/asn.1/types.hpp>
#include <sdk/io/basic/parser.hpp>

namespace hotplace {
namespace io {

class asn1 {
   public:
    asn1();
    asn1(const asn1& rhs);
    virtual ~asn1();

    asn1* clone();

    // types
    asn1& add_type(asn1_object* item);
    asn1& operator<<(asn1_object* item);

    /**
     * @brief   values
     * @sample
     *          set_value_byname("name", "Smith").set_value_byname("ok", true);
     */
    asn1& set_value_byname(const std::string& name, const variant& value);
    asn1& set_value_byname(const std::string& name, variant&& value);
    asn1& set_value_byindex(unsigned index, const variant& value);
    asn1& set_value_byindex(unsigned index, variant&& value);
    asn1_object* operator[](const std::string& name);
    asn1_object* operator[](unsigned index);

    void publish(binary_t* b);
    void publish(stream_t* s);

    void addref();
    void release();

    void clear();

   protected:
   private:
    t_shared_reference<asn1> _ref;
    std::list<asn1_object*> _types;

    typedef std::map<std::string, asn1_object*> dictionary_t;
    typedef std::map<std::string, variant> namevalues_t;
    typedef std::map<unsigned, variant> indexvalues_t;

    dictionary_t _dictionary;
    namevalues_t _namevalues;
    indexvalues_t _idxvalues;

    parser _parser;
};

}  // namespace io
}  // namespace hotplace

#endif
