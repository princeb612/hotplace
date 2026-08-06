/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_runtime.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_RUNTIME_ASN1__
#define __HOTPLACE_SDK_IO_ASN1_RUNTIME_ASN1__

#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/base/nostd/tree.hpp>
#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/types.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_weakly_typed.hpp>
// #include <hotplace/sdk/io/basic/parser.hpp>

namespace hotplace {
namespace io {

class asn1_runtime {
    friend class asn1_weakly_typed;

   public:
    asn1_runtime();
    asn1_runtime(const asn1_runtime& other);
    virtual ~asn1_runtime();

    asn1_runtime& operator=(const asn1_runtime& other);

    asn1_runtime* clone();

    asn1_runtime& add(asn1_object* item);
    asn1_runtime& add(asn1_object* item, std::function<void(asn1_object*)> f);
    asn1_runtime& operator<<(asn1_object* item);

    return_t set(asn1_object* item, asn1_value* value);
    asn1_value* get(asn1_object* item) const;

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
    return_t postread(const byte_t* stream, size_t size);

   private:
    t_shared_reference<asn1_runtime> _shared;

    std::map<std::string, asn1_object*> _dictionary;
    std::list<asn1_object*> _types;
    std::map<asn1_object*, asn1_value*> _values;

    // parser _parser;
};

}  // namespace io
}  // namespace hotplace

#endif
