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

#ifndef __HOTPLACE_SDK_IO_ASN1_ASN1RESOURCE__
#define __HOTPLACE_SDK_IO_ASN1_ASN1RESOURCE__

#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/io/asn.1/types.hpp>

namespace hotplace {
namespace io {

class asn1_resource {
   public:
    static asn1_resource* get_instance();

    std::string get_type_name(asn1_type_t t);
    asn1_type_t get_type(const std::string& name);
    std::string get_class_name(int c);
    /**
     * @brief   IMPLICIT/EXPLICIT
     */
    std::string get_tagtype_name(uint32 t);
    std::string get_componenttype_name(uint32 t);

    void for_each_type_name(std::function<void(asn1_type_t, const std::string&)> f);

   protected:
    asn1_resource();
    void load_resource();
    void doload_resource();

   private:
    static asn1_resource _instance;

    critical_section _lock;
    std::map<asn1_type_t, std::string> _type_id;
    std::map<std::string, asn1_type_t> _type_rid;
    std::map<int, std::string> _class_id;
};

}  // namespace io
}  // namespace hotplace

#endif
