/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/nostd/exception.hpp>

namespace hotplace {

exception::exception(errorcode_t err) { _errorcode = err; }

exception::exception(errorcode_t err, const std::string& desc) : _errorcode(err), _desc(desc) {}

exception::exception(const exception& rhs) : _errorcode(rhs._errorcode), _desc(rhs._desc) {}

exception::exception(exception&& rhs) : _errorcode(rhs._errorcode), _desc(std::move(rhs._desc)) {}

errorcode_t exception::get_errorcode() const { return _errorcode; }

std::string exception::get_error_message() const {
    std::string msg;
    error_advisor::get_instance()->error_message(_errorcode, msg);
    return msg;
}

std::string exception::get_description() const { return _desc; }

}  // namespace hotplace
