/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_COMPRESSION_HTTPSTATICTABLE__
#define __HOTPLACE_SDK_NET_HTTP_COMPRESSION_HTTPSTATICTABLE__

#include <hotplace/sdk/net/http/compression/http_header_compression.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   static table
 * @remarks cannot access directly, use hpack_static_table or qpack_static_table instead
 */
class http_static_table {
   public:
    /**
     * @brief   match
     * @param   uint32 flags [in]
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     * @param   size_t& index [out]
     * @return  error code (see error.hpp)
     */
    virtual match_result_t match(uint32 flags, const std::string& name, const std::string& value, size_t& index);
    /**
     * @brief   select
     * @param   uint32 flags [in]
     * @param   size_t index [in]
     * @param   std::string& name [out]
     * @param   std::string& value [out]
     * @return  error code (see error.hpp)
     */
    virtual return_t select(uint32 flags, size_t index, std::string& name, std::string& value);
    /**
     * @brief   size
     * @return  size of static table
     */
    virtual size_t size();

   protected:
    http_static_table();

    virtual void load();

   protected:
    typedef std::pair<std::string, size_t> table_entry_t;
    typedef std::multimap<std::string, table_entry_t> static_table_t;
    typedef std::map<size_t, std::pair<std::string, std::string>> static_table_index_t;

    critical_section _lock;
    static_table_t _static_table;
    static_table_index_t _static_table_index;
};

}  // namespace net
}  // namespace hotplace

#endif
