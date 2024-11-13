/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.08.13   Soo Han, Kim        reboot (codename.hotplace)
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_ERROR__
#define __HOTPLACE_SDK_BASE_SYSTEM_ERROR__

#include <sdk/base/system/critical_section.hpp>

namespace hotplace {

typedef struct _error_description {
    errorcode_t error;
    const char* error_code;
    const char* error_message;
} error_description;

class error_advisor {
   public:
    static error_advisor* get_instance();

    bool error_code(return_t error, std::string& code);
    bool error_message(return_t error, std::string& message);

   protected:
    error_advisor();
    void build();
    bool find(return_t error, const error_description** desc);

   private:
    static error_advisor _instance;

    typedef std::map<return_t, const error_description*> error_description_map_t;
    critical_section _lock;
    error_description_map_t _table;
};

}  // namespace hotplace

#endif
