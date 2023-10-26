/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/io/system/windows/windows_registry.hpp>

namespace hotplace {
namespace io {

windows_registry::windows_registry() {
    // do nothing
}

windows_registry::~windows_registry() {
    // do nothing
}

return_t windows_registry::close_key(HKEY hKey) {
    // treat LSTATUS as return_t
    return RegCloseKey(hKey);
}

}  // namespace io
}  // namespace hotplace
