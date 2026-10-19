
/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   oid_dictionary.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_BASIC_OIDDICTIONARY__
#define __HOTPLACE_SDK_IO_BASIC_OIDDICTIONARY__

#include <hotplace/sdk/base/pattern/trie.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/io/basic/oid.hpp>
#include <hotplace/sdk/io/types.hpp>

namespace hotplace {
namespace io {

struct oid_metadata {
    std::string name;
    std::string description;
};

class oid_dictionary {
   public:
    static oid_dictionary* get_instance();
    ~oid_dictionary();

    void insert(const std::string& oidstr, const std::string& name, const std::string& description);
    void insert(const oid_t& oid, const std::string& name, const std::string& description);
    bool lookup(const std::string& oidstr, oid_metadata& metadata) const;
    bool lookup(const oid_t& oid, oid_metadata& metadata) const;

   protected:
    oid_dictionary();
    void load();  // certificate, hash, curves

   private:
    t_trie<uint32, uint32, oid_metadata> trie;
    mutable critical_section _lock;
    int _load{0};
};

}  // namespace io
}  // namespace hotplace

#endif
