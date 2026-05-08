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

#ifndef __HOTPLACE_SDK_BASE_BASIC_EXCEPTION__
#define __HOTPLACE_SDK_BASE_BASIC_EXCEPTION__

#include <sdk/base/error.hpp>
#include <sdk/base/stl.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>

namespace hotplace {

class exception {
   private:
    errorcode_t _errorcode;
    std::string _desc;

   public:
    exception(errorcode_t err) { _errorcode = err; }
    exception(errorcode_t err, const std::string& desc) : _errorcode(err), _desc(desc) {}
    exception(const exception& rhs) : _errorcode(rhs._errorcode), _desc(rhs._desc) {}
    exception(exception&& rhs) : _errorcode(rhs._errorcode), _desc(std::move(rhs._desc)) {}

    errorcode_t get_errorcode() const { return _errorcode; }
    std::string get_error_message() const {
        std::string msg;
        error_advisor::get_instance()->error_message(_errorcode, msg);
        return msg;
    }
    std::string get_description() const { return _desc; }
};

}  // namespace hotplace

#endif
