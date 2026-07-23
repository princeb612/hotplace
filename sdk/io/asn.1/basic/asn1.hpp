/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_ASN1__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_ASN1__

#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/base/nostd/tree.hpp>
#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_weak_typed.hpp>
#include <hotplace/sdk/io/asn.1/types.hpp>
// #include <hotplace/sdk/io/basic/parser.hpp>

namespace hotplace {
namespace io {

class asn1 {
   public:
    asn1();
    asn1(const asn1& other);
    virtual ~asn1();

    asn1& operator=(const asn1& other);

    asn1* clone();

    static asn1_object* make_builtin_type(asn1_entity_t entity, std::function<void(asn1_object*)> f = nullptr);

    asn1& add(asn1_object* item);
    asn1& add(asn1_object* item, std::function<void(asn1_object*)> f);
    asn1& operator<<(asn1_object* item);

    return_t read(const byte_t* stream, size_t size, size_t& pos);
    void for_each(std::function<void(asn1_object*)> f) const;
    void for_each(std::function<void(asn1_value*)> f) const;
    void notation(stream_t* s);
    void publish(stream_t* s);
    void publish(binary_t* b);

    void clear();

    void addref();
    void release();

   protected:
   private:
    t_shared_reference<asn1> _shared;

    std::map<std::string, asn1_object*> _dictionary;
    std::list<asn1_object*> _types;
    std::list<asn1_value*> _values;

    // parser _parser;
};

}  // namespace io
}  // namespace hotplace

#endif
