/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   error.hpp
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
#include <hotplace/sdk/base/system/error.hpp>
#include <hotplace/sdk/base/system/types.hpp>
#include <queue>

namespace hotplace {

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

   private:
    static error_advisor _instance;

    typedef std::map<return_t, const error_description*> error_description_map_t;
    critical_section _lock;
    error_description_map_t _table;
};

struct errno_category {};
struct osslerror_category {};

template <typename T, typename category = void>
struct error_traits;

/* hotplace return_t/errorcode_t */
template <>
struct error_traits<return_t> {
    static return_t value_success() { return errorcode_t::success; }
    static return_t value_exception() { return errorcode_t::exception_caught; }
    static return_t value_invalid_parameter() { return errorcode_t::invalid_parameter; }
    static return_t value_internal_error() { return errorcode_t::internal_error; }
    static bool is_success(return_t code) { return (code == errorcode_t::success) || (code == errorcode_t::expect_failure); }
    static bool is_not_fail(return_t code) {
        auto category = error_advisor::get_instance()->categoryof(code);
        return (error_category_t::error_category_severe != category);
    }
    static return_t to_return_t(return_t code) { return code; }
    static return_t from_return_t(return_t code) { return code; }
};

/* linux errno */
template <>
struct error_traits<int, errno_category> {
    static int value_success() { return 0; }
    static int value_exception() { return /* eai_fail */ -4; }
    static int value_invalid_parameter() { return /* ebadrqc */ 56; }
    static int value_internal_error() { return /* eai_fail */ -4; }
    static bool is_success(int code) { return code == 0; }
    static bool is_not_fail(int code) { return code == 0; }
    static return_t to_return_t(int code) { return is_success(code) ? errorcode_t::success : errorcode_t::internal_error; }
    static int from_return_t(return_t code) { return error_traits<return_t>::is_success(code) ? value_success() : value_internal_error(); }
};

/* openssl specialization */
template <>
struct error_traits<int, osslerror_category> {
    static int value_success() { return 1; }
    static int value_exception() { return -1; }
    static int value_invalid_parameter() { return 0; }
    static int value_internal_error() { return 0; }
    static bool is_success(int code) { return code > 0; }
    static bool is_not_fail(int code) { return code > 0; }
    static return_t to_return_t(int code) { return is_success(code) ? errorcode_t::success : errorcode_t::error_openssl_inside; }
    static int from_return_t(return_t code) { return error_traits<return_t>::is_success(code) ? value_success() : value_internal_error(); }
};

}  // namespace hotplace

#endif
