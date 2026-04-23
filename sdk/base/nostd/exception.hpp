/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   exception.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_NOSTD_EXCEPTION__
#define __HOTPLACE_SDK_BASE_NOSTD_EXCEPTION__

#include <hotplace/sdk/base/system/types.hpp>

namespace hotplace {

class exception {
   private:
    errorcode_t _errorcode;
    std::string _desc;

   public:
    exception(errorcode_t err);
    exception(errorcode_t err, const std::string& desc);
    exception(const exception& other);
    exception(exception&& other);

    exception& operator=(const exception& other);
    exception& operator=(exception&& other);

    errorcode_t get_errorcode() const;
    std::string get_error_message() const;
    std::string get_description() const;
};

}  // namespace hotplace

#endif
