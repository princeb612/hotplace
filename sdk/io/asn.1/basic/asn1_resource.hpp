/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_resource.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_ASN1RESOURCE__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_ASN1RESOURCE__

#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/io/asn.1/basic/types.hpp>

namespace hotplace {
namespace io {

struct asn1_entity_resource_t {
    asn1_entity_t type;
    const char* token;
    asn1_perm_t permission;
    uint32 tokenid;
};

extern const struct asn1_entity_resource_t resource_asn1_entities[];
extern const size_t sizeof_resource_asn1_entities;

class asn1_resource {
   public:
    static asn1_resource* get_instance();

    std::string get_component_entity_name(asn1_entity_t entity) const;
    std::string get_entity_name(uint8 ident, asn1_entity_t entity) const;
    asn1_entity_t get_entity(const std::string& name) const;
    asn1_perm_t get_perm(asn1_entity_t entity) const;
    std::string get_class_name(int c) const;
    uint8 get_class(const std::string& name) const;
    /**
     * @brief   IMPLICIT/EXPLICIT/DEFAULT/OPTIONAL
     */
    std::string nameof_mode(uint16 t) const;
    uint8 valueof_mode(const std::string& name) const;

    template <typename F>  // void(uint32 tokenid, const std::string& name)
    void for_each(resource_type_t type, F f) const {
        for (size_t i = 0; i < sizeof_resource_asn1_entities; ++i) {
            auto entry = resource_asn1_entities[i];
            if (entry.tokenid && entry.token) {
                std::forward<F>(f)(entry.tokenid, entry.token);
            }
        }
    }

   protected:
    asn1_resource();
    void load_resource();
    void doload_resource();

   private:
    static asn1_resource _instance;

    critical_section _lock;
    std::map<asn1_entity_t, std::string> _type_id;
    std::map<std::string, asn1_entity_t> _type_rid;
    std::map<asn1_entity_t, asn1_perm_t> _type_perm;
    std::map<int, std::string> _class_id;
    std::map<std::string, int> _class_rid;
    std::map<int, std::string> _mode_id;
    std::map<std::string, int> _mode_rid;
};

}  // namespace io
}  // namespace hotplace

#endif
