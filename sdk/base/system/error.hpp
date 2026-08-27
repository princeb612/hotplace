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
    static constexpr return_t value_success() noexcept { return errorcode_t::success; }
    static constexpr return_t value_exception() noexcept { return errorcode_t::exception_caught; }
    static constexpr return_t value_invalid_parameter() noexcept { return errorcode_t::invalid_parameter; }
    static constexpr return_t value_internal_error() noexcept { return errorcode_t::internal_error; }

    static constexpr bool is_success(return_t code) noexcept { return (code == errorcode_t::success) || (code == errorcode_t::expect_failure); }

    static bool is_not_fail(return_t code) {
        auto category = error_advisor::get_instance()->categoryof(code);
        return (error_category_t::error_category_severe != category);
    }

    static constexpr return_t to_return_t(return_t code) noexcept { return code; }
    static constexpr return_t from_return_t(return_t code) noexcept { return code; }

    static constexpr bool compare(return_t lhs, return_t rhs) noexcept { return lhs == rhs; }
};

/* linux errno */
template <>
struct error_traits<int, errno_category> {
    static constexpr int value_success() noexcept { return 0; }
    static constexpr int value_exception() noexcept { return -4; /* eai_fail */ }
    static constexpr int value_invalid_parameter() noexcept { return 56; /* ebadrqc */ }
    static constexpr int value_internal_error() noexcept { return -4; /* eai_fail */ }

    static constexpr bool is_success(int code) noexcept { return code == 0; }
    static constexpr bool is_not_fail(int code) noexcept { return code == 0; }

    static constexpr return_t to_return_t(int code) noexcept { return is_success(code) ? errorcode_t::success : errorcode_t::internal_error; }
    static constexpr int from_return_t(return_t code) noexcept { return error_traits<return_t>::is_success(code) ? value_success() : value_internal_error(); }

    static constexpr bool compare(int lhs, return_t rhs) noexcept { return to_return_t(lhs) == rhs; }
    static constexpr bool compare(return_t lhs, int rhs) noexcept { return lhs == to_return_t(rhs); }
};

/* openssl specialization */
template <>
struct error_traits<int, osslerror_category> {
    static constexpr int value_success() noexcept { return 1; }
    static constexpr int value_exception() noexcept { return -1; }
    static constexpr int value_invalid_parameter() noexcept { return 0; }
    static constexpr int value_internal_error() noexcept { return 0; }

    // OpenSSL 성공 판단 조건 수정: code > 0
    static constexpr bool is_success(int code) noexcept { return code > 0; }
    static constexpr bool is_not_fail(int code) noexcept { return code > 0; }

    static constexpr return_t to_return_t(int code) noexcept { return is_success(code) ? errorcode_t::success : errorcode_t::error_openssl_inside; }
    static constexpr int from_return_t(return_t code) noexcept { return error_traits<return_t>::is_success(code) ? value_success() : value_internal_error(); }

    static constexpr bool compare(int lhs, return_t rhs) noexcept { return to_return_t(lhs) == rhs; }
    static constexpr bool compare(return_t lhs, int rhs) noexcept { return lhs == to_return_t(rhs); }
};

template <typename T, typename errno_category>
constexpr inline return_t to_return_t(T code) noexcept {
    return error_traits<T, errno_category>::to_return_t_const(code);
}

}  // namespace hotplace

#endif
