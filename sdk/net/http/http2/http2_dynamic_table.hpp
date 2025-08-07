/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP2_HTTP2DYNAMICTABLE__
#define __HOTPLACE_SDK_NET_HTTP_HTTP2_HTTP2DYNAMICTABLE__

#include <functional>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/net/http/http2/http_header_compression.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   dynamic table
 * @sa      hpack_dynamic_table, qpack_dynamic_table
 */
class http2_dynamic_table {
   public:
    virtual ~http2_dynamic_table();
    /**
     * @brief   for_each
     * @sample
     *          auto lambda = [&](size_t entno, size_t entsize, const std::string& name, const std::string& value) -> void {
     *              _logger->writeln("  - [%3zi](s = %zi) %s: %s", entno, entsize, name.c_str(), value.c_str());
     *          };
     *
     */
    virtual void for_each(std::function<void(size_t, size_t, const std::string&, const std::string&)> f);
    virtual void dump(const std::string& desc, std::function<void(const char*, size_t)> f);
    /**
     * @brief   compare
     */
    bool operator==(const http2_dynamic_table& rhs);
    bool operator!=(const http2_dynamic_table& rhs);
    /**
     * @brief   match
     * @param   uint32 flags [in]
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     * @param   size_t& index [out]
     * @return  match_result_t
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
     * @brief   insert into queue
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     * @return  error code (see error.hpp)
     */
    virtual return_t insert(const std::string& name, const std::string& value);
    /**
     * @brief   commit queue
     */
    virtual return_t commit();
    /**
     * @brief   evict
     * @return  error code (see error.hpp)
     */
    virtual return_t evict();
    /**
     * @brief   capacity (SETTINGS_QPACK_MAX_TABLE_CAPACITY)
     */
    void set_capacity(uint32 capacity);
    size_t get_capacity();
    /**
     * @brief   table size
     */
    size_t get_tablesize();
    /**
     * @brief   entries
     */
    size_t get_entries();
    /**
     * @brief   HPACK/QPACK query function
     * @param   int cmd [in] see header_compression_cmd_t
     * @param   void* req [in]
     * @param   size_t reqsize [in]
     * @param   void* resp [out]
     * @param   size_t& respsize [inout]
     * @return  error code (see error.hpp)
     */
    virtual return_t query(int cmd, void* req, size_t reqsize, void* resp, size_t& respsize);
    /**
     * @brief   type
     * @return  see header_compression_type_t
     */
    uint8 get_type();

    void set_debug_hook(std::function<void(trace_category_t, uint32 event)> fn);

    void ack();
    void cancel();
    void increment(size_t inc);

   protected:
    http2_dynamic_table();

    void set_type(uint8 type);
    size_t dynamic_map_size();
    void pick(size_t entry, const std::string& name, std::string& value);

    critical_section _lock;
    uint32 _capacity;
    size_t _inserted;
    size_t _dropped;
    size_t _ack;  // qpack

    typedef std::pair<std::string, size_t> table_entry_t;
    typedef std::multimap<std::string, table_entry_t> dynamic_map_t;  // table_entry_t(value, entry)
    typedef std::map<size_t, table_entry_t> dynamic_reversemap_t;     // pair(entry, table_entry_t(name, entry size))
    struct commit_pair {
        std::string name;
        std::string value;
    };
    typedef std::queue<commit_pair> commit_queue_t;

    dynamic_map_t _dynamic_map;
    dynamic_reversemap_t _dynamic_reversemap;
    commit_queue_t _commit_queue;

   private:
    uint8 _type;  // see header_compression_type_t
    size_t _tablesize;

    std::function<void(trace_category_t, uint32 event)> _hook;
};

}  // namespace net
}  // namespace hotplace

#endif
