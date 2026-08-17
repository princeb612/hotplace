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

#ifndef __HOTPLACE_SDK_IO_ASN1_RUNTIME_ASN1RUNTIME__
#define __HOTPLACE_SDK_IO_ASN1_RUNTIME_ASN1RUNTIME__

#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/types.hpp>
#include <set>

namespace hotplace {
namespace io {

class asn1_runtime {
    friend class asn1_weakly_typed;

   public:
    asn1_runtime();
    asn1_runtime(const std::string& name);
    asn1_runtime(const asn1_runtime& other);
    virtual ~asn1_runtime();

    asn1_runtime& operator=(const asn1_runtime& other);

    asn1_runtime* clone();

    return_t add(asn1_object* item);
    asn1_runtime& add(asn1_object* item, std::function<void(asn1_object*)> f);
    asn1_runtime& operator<<(asn1_object* item);

    return_t set(asn1_object* item, asn1_value* value);
    asn1_object* get(const std::string& name) const;
    asn1_value* get(asn1_object* item) const;

    /**
     * @brief   weakly-typed (schema-less)
     * @sample
     *          asn1_runtime runtime;
     *          asn1_weakly_typed weaktype;
     *          size_t pos = 0;
     *          weaktype.read_weakly_typed(&runtime, stream, size, pos);
     */
    return_t read_weakly_typed(const byte_t* stream, size_t size, size_t& pos);

    // strongly-typed
    return_t add_schema(const std::string& schema, asn1_object* item);
    // TODO
    // - add_schema skip from_schema
    asn1_object* from_schema(const std::string& schema);
    /**
     * @brief   strongly-typed
     * @sample
     *          const char* schema1 = "Type1 ::= VisibleString";
     *          asn1_object* type1 = asn1_referenced_type::define("type1", new asn1_visiblestring);
     *          const char* schema2 = "Type2 ::= [APPLICATION 3] IMPLICIT Type1";
     *          asn1_object* type2 = asn1_referenced_type::define("type2", new asn1_tagged_type(asn1_class_application, 3, asn1_implicit,
     * asn1_referenced_type::refer("type1"))); const char* schema3 = "Type3 ::= [2] EXPLICIT Type2"; asn1_object* type3 = asn1_referenced_type::define("type3", new
     * asn1_tagged_type(asn1_class_context, 2, asn1_explicit, asn1_referenced_type::refer("type2")));
     *
     *          asn1_runtime runtime;
     *          runtime.add_schema(schema1, type1);
     *          runtime.add_schema(schema2, type2);
     *          runtime.add_schema(schema3, type3);
     *
     *          const char* bytestream = "A2 07 43 05 4A 6F 6E 65 73";
     *          binary_t bin_stream = base16_decode_rfc(bytestream);
     *          auto stream = bin_stream.data();
     *          auto size = bin_stream.size();
     *          size_t pos = 0;
     *          runtime.read("type3", stream, size, pos);
     */
    return_t read(const std::string& name, const byte_t* stream, size_t size, size_t& pos);

    void for_each(std::function<void(asn1_object*)> f) const;
    void for_each(std::function<void(asn1_value*)> f) const;
    void notation(stream_t* s);
    void publish(stream_t* s);
    void publish(binary_t* b);
    void notation(const std::string& name, stream_t* s);
    void publish(const std::string& name, stream_t* s);
    void publish(const std::string& name, binary_t* b);

    // replace reference
    void update_linkage(asn1_object* object);

    void set_name(const std::string& name);
    std::string get_name();

    /**
     * - module-level
     *   - MyModule DEFINITIONS ::= BEGIN ...
     *   - MyModule DEFINITIONS IMPLICIT TAGS ::= BEGIN ...
     *   - MyModule DEFINITIONS AUTOMATIC TAGS ::= BEGIN ...
     * - default EXPLICIT
     * - CHOICE, ANY MUST be EXPLICIT
     */
    void set_automatic(uint8 runas);
    uint8 runas_automatic();

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
    std::map<asn1_object*, std::string> _schema;  // strongly-typed
    std::string _name;
    // parser _parser;
    uint8 _automatic;
};

}  // namespace io
}  // namespace hotplace

#endif
