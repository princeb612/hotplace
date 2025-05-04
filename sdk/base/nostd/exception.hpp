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

#ifndef __HOTPLACE_SDK_BASE_NOSTD_EXCEPTION__
#define __HOTPLACE_SDK_BASE_NOSTD_EXCEPTION__

#include <sdk/base/error.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/system/error.hpp>
#include <sdk/base/types.hpp>

namespace hotplace {

class exception {
   private:
    errorcode_t _errorcode;
    std::string _desc;

   public:
    exception(errorcode_t err);
    exception(errorcode_t err, const std::string& desc);
    exception(const exception& rhs);
    exception(exception&& rhs);

    errorcode_t get_errorcode() const;
    std::string get_error_message() const;
    std::string get_description() const;
};

}  // namespace hotplace

#endif
