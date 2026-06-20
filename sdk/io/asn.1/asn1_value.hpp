/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_value.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_ASN1VALUE__
#define __HOTPLACE_SDK_IO_ASN1_ASN1VALUE__

#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/io/asn.1/types.hpp>

namespace hotplace {
namespace io {

/**
    // sketch.1
    {
        auto schema = new asn1_builtin_type(asn1_entity_visiblestring);
        auto instance = schema->instantiate();

        (*instance) << "sample";      // operator <<

        (*instance)[""] = "sample";   // operator [](const std::string&)

        instance->set("", "sample");  // set
    }

    // scketch.2
    {
        auto schema = new asn1_sequence;
        (*schema) << new asn1_builtin_type("name", asn1_entity_utf8string)
                  << new asn1_builtin_type("age", asn1_entity_utf8string)
                  << new asn1_builtin_type("profile", new asn1_builtin_type("Profile", asn1_entity_referenced_type));
        auto instance = schema->instantiate();

        (*instance) << "john" << "20" << "...";

        (*instance)["name"] = "john";
        (*instance)["age"] = "20";
        (*instance)["profile"] = "...";

        (*instance).set("name", "john").set("age", "20").set("profile", "...");
    }
 */
class asn1_value {
   public:
    asn1_value(asn1_object* schema);
    ~asn1_value();

    asn1_object* get_schema();

    asn1_value& set(const variant& vt);
    asn1_value& set(std::initializer_list<variant> items);
    asn1_value& set(const std::string& name, const variant& vt);
    asn1_value& set(const std::string& name, std::initializer_list<variant> items);
    asn1_value& set(const std::string& name, variant&& vt);

    void publish(stream_t* b);
    void publish(binary_t* b);
    void write(stream_t* s, const std::string& name);
    bool find(const std::string& name);
    void encode_value(binary_t& bin, asn1_object* object, const std::string& name, bool& do_len);
    void encode_sequenceof_value(binary_t& bin, asn1_object* object, const std::string& name);
    void encode_setof_value(binary_t& bin, asn1_object* object, const std::string& name);

    void addref();
    void release();

   protected:
   private:
    asn1_object* _schema;
    std::multimap<std::string, variant> _values;

    t_shared_reference<asn1_value> _shared;
};

}  // namespace io
}  // namespace hotplace

#endif
