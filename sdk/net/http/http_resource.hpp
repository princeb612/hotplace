/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_RESOURCE__
#define __HOTPLACE_SDK_NET_HTTP_RESOURCE__

#include <map>
#include <sdk/net/http/types.hpp>

namespace hotplace {
namespace net {

class http_resource {
   public:
    /**
     * @brief   singleton instance
     */
    static http_resource* get_instance();

    /**
     * @brief   status code message
     * @remarks RFC 2616 HTTP/1.1 6.1.1 Status Code and Reason Phrase
     */
    std::string load(int status);
    /**
     * @brief   method
     */
    std::string get_method(http_method_t method);
    /**
     * @brief   frame name
     */
    std::string get_frame_name(uint8 type);
    /**
     * @brief   frame flag
     */
    std::string get_frame_flag(uint8 flag);
    void for_each_frame_flag_names(uint8 type, uint8 flags, std::function<void(uint8, const std::string&)> func);

    /**
     * @brief   RFC 7541 Appendix A.  Static Table Definition
     */
    void for_each_hpack_static_table(std::function<void(uint32 index, const char* name, const char* value)> func);
    size_t sizeof_hpack_static_table_entries();
    /**
     * @brief   RFC 9204 Appendix A.  Static Table
     */
    void for_each_qpack_static_table(std::function<void(uint32 index, const char* name, const char* value)> func);
    size_t sizeof_qpack_static_table_entries();

   protected:
    http_resource();
    void load_resources();
    void doload_resources();

   private:
    static http_resource _instance;
    critical_section _lock;
    std::map<int, std::string> _status_codes;
    std::map<http_method_t, std::string> _methods;
    std::map<uint8, std::string> _frame_names;
    std::map<uint8, std::string> _frame_flags;
    std::map<uint8, std::string> _frame_flags2;
};

}  // namespace net
}  // namespace hotplace

#endif
