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

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTPRESOURCE__
#define __HOTPLACE_SDK_NET_HTTP_HTTPRESOURCE__

#include <map>
#include <sdk/net/http/types.hpp>

namespace hotplace {
namespace net {

/**
 * internal data structure
 */
struct http_static_table_entry {
    uint32 index;
    const char* name;
    const char* value;
};

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
    std::string get_h2_frame_name(uint8 type);
    /**
     * @brief   frame flag
     */
    std::string get_h2_frame_flag(uint8 flag);
    void for_each_h2_frame_flag_names(uint8 type, uint8 flags, std::function<void(uint8, const std::string&)> func);

    /**
     * @brief   SETTINGS
     * @remarks RFC 7540 6.5.2.  Defined SETTINGS Parameters
     */
    std::string get_h2_settings_name(uint16 type);

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

    std::string get_h2_error_string(uint16 code);

    std::string get_h3_stream_name(uint8 type);
    std::string get_h3_frame_name(uint64 type);
    std::string get_h3_error_string(uint16 code);
    std::string get_h3_settings_name(uint64 id);

   protected:
    http_resource();
    void load_resources();
    void doload_resources();
    void doload_resources_h1();
    void doload_resources_h2();
    void doload_resources_h3();

   private:
    static http_resource _instance;
    critical_section _lock;
    std::map<int, std::string> _status_codes;
    std::map<http_method_t, std::string> _methods;
    std::map<uint8, std::string> _h2_frame_names;
    std::map<uint8, std::string> _h2_frame_flags;
    std::map<uint8, std::string> _h2_frame_flags2;
    std::map<uint8, std::string> _h3_stream_names;
    std::map<uint16, std::string> _h2_frame_settings;
    std::map<uint64, std::string> _h3_frame_names;
    std::map<uint32, std::string> _h2_error_codes;
    std::map<uint16, std::string> _h3_error_codes;
    std::map<uint64, std::string> _h3_frame_settings;
};

}  // namespace net
}  // namespace hotplace

#endif
