/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/evp_key.hpp>

namespace hotplace {
namespace crypto {

constexpr char constexpr_pem[] = "PEM";
constexpr char constexpr_der[] = "DER";
constexpr char constexpr_privkeyinfo[] = "PrivateKeyInfo";
constexpr char constexpr_encryptedprivkeyinfo[] = "EncryptedPrivateKeyInfo";
constexpr char constexpr_pubkeyinfo[] = "SubjectPublicKeyInfo";

return_t crypto_advisor::get_encoding_params(key_encoding_t encoding, key_encoding_params_t& params) {
    return_t ret = errorcode_t::success;
    __try2 {
        const char* format = nullptr;
        const char* structure = nullptr;
        int selection = 0;
        bool use_pass = false;
        switch (encoding) {
            case key_encoding_priv_pem: {
                params.selection = OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS;
                params.format = constexpr_pem;
                params.structure = constexpr_privkeyinfo;
                params.use_pass = false;
            } break;
            case key_encoding_encrypted_priv_pem: {
                params.selection = OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;
                params.format = constexpr_pem;
                params.structure = constexpr_encryptedprivkeyinfo;
                params.use_pass = true;
            } break;
            case key_encoding_pub_pem: {
                params.selection = OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS;
                params.format = constexpr_pem;
                params.structure = constexpr_pubkeyinfo;
                params.use_pass = false;
            } break;
            case key_encoding_priv_der: {
                params.selection = OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS;
                params.format = constexpr_der;
                params.structure = constexpr_privkeyinfo;
                params.use_pass = false;
            } break;
            case key_encoding_encrypted_priv_der: {
                params.selection = OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;
                params.format = constexpr_der;
                params.structure = constexpr_encryptedprivkeyinfo;
                params.use_pass = true;
            } break;
            case key_encoding_pub_der: {
                params.selection = OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS;
                params.format = constexpr_der;
                params.structure = constexpr_pubkeyinfo;
                params.use_pass = false;
            } break;
            default: {
                ret = errorcode_t::not_supported;
            }
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {}
    return ret;
}

std::string crypto_advisor::nameof_encoding(key_encoding_t encoding) {
    std::string value;
    switch (encoding) {
        case key_encoding_priv_pem: {
            value = "PEM private key";
        } break;
        case key_encoding_encrypted_priv_pem: {
            value = "PEM encrypted private key";
        } break;
        case key_encoding_pub_pem: {
            value = "PEM public key";
        } break;
        case key_encoding_priv_der: {
            value = "DER private key";
        } break;
        case key_encoding_encrypted_priv_der: {
            value = "DER encrypted private key";
        } break;
        case key_encoding_pub_der: {
            value = "DER public key";
        } break;
    }
    return value;
}

}  // namespace crypto
}  // namespace hotplace
