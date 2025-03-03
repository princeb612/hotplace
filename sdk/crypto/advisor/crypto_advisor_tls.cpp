/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/crypto_advisor.hpp>

namespace hotplace {
namespace crypto {

const hint_curve_t* crypto_advisor::hintof_tls_group(uint16 group) {
    const hint_curve_t* item = nullptr;
    t_maphint<uint16, const hint_curve_t*> hint(_tls_group_map);

    hint.find(group, &item);
    return item;
}

}  // namespace crypto
}  // namespace hotplace
