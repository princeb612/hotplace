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

#include <hotplace/sdk/base/system/critical_section.hpp>
#include <queue>

namespace hotplace {

/**
 * @sa error_advisor::categoryof
 */
enum error_category_t : uint8 {
    error_category_success = 0,         // success
    error_category_expect_failure = 1,  // success (negative test)
    error_category_severe = 2,          // severe error
    error_category_not_supported = 3,   // do not support
    error_category_low_security = 4,    // do not support (security reason)
    error_category_trivial = 5,         // debugging purpose
    error_category_warn = 6,            // warning
};

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
    bool error_message(return_t error, std::string& code, std::string& message);

    error_category_t categoryof(return_t code);

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
