/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   openssl_kdf_aes.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/system/types.hpp>
#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/openssl_hash.hpp>
#include <hotplace/sdk/crypto/basic/openssl_kdf.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>
#include <hotplace/sdk/crypto/basic/types.hpp>

#if defined __linux__
#include <dlfcn.h>
#include <sys/time.h>
#include <unistd.h>
#endif

namespace hotplace {
namespace crypto {

return_t openssl_kdf::hkdf_expand_aes_rfc8152(binary_t& okm, const char* alg, size_t dlen, const binary_t& prk, const binary_t& info) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    openssl_mac mac;

    __try2 {
        // the CKDF-Expand(PRK, info, L) function takes the PRK result from CKDF-Extract, an arbitrary "info" argument and a requested number of bytes to
        // produce. It calculates the L-byte result, called the "output keying material" (OKM)

        okm.clear();

        if (nullptr == alg) {
            __leave2;
        }

        const hint_blockcipher_t* hint = advisor->hintof_blockcipher(alg);
        if (nullptr == hint) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        const EVP_CIPHER* cipher = advisor->find_evp_cipher(alg);
        if (nullptr == cipher) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        EVP_CIPHER_CTX_ptr context(EVP_CIPHER_CTX_new());
        if (nullptr == context.get()) {
            ret = errorcode_t::out_of_memory;
            __leave2;
        }

        binary_t iv;
        uint16 blocksize = sizeof_block(hint);
        size_t offset = 0;
        binary_t t_block;  // T(0) = empty string (zero length)
        int t_block_size = 0;
        int size_update = 0;
        iv.resize(16);

        EVP_CIPHER_CTX_set_padding(context.get(), 1);

        for (size_t i = 1; offset < dlen /* N = ceil(L/Hash_Size) */; ++i) {
            binary_t content;  // T(1) = AES-CMAC(PRK, T(0) | info | 0x01)
            content.insert(content.end(), t_block.begin(), t_block.end());
            content.insert(content.end(), info.begin(), info.end());
            content.insert(content.end(), uint8(i));  // i = 1..255 (01..ff)

            // T(i) = AES-CMAC(PRK, T(i-1) | info | i), i = 1..255 (01..ff)
            if (0 == t_block_size) {
                t_block_size = blocksize;
                t_block.resize(blocksize);
            }

            EVP_CipherInit_ex(context.get(), cipher, nullptr, prk.data(), iv.data(), 1);

            int size_update = 0;
            size_t size_input = content.size();
            for (size_t j = 0; j < size_input; j += blocksize) {
                auto remain = size_input - j;
                auto size = (remain < blocksize) ? remain : blocksize;
                if (remain > blocksize) {
                    EVP_CipherUpdate(context.get(), t_block.data(), &size_update, &content[j], blocksize);
                } else {
                    EVP_CipherUpdate(context.get(), t_block.data(), &size_update, &content[j], t_narrow_cast(remain));
                    EVP_CipherUpdate(context.get(), t_block.data(), &size_update, iv.data(), t_narrow_cast(blocksize - remain));
                }
            }

            okm.insert(okm.end(), t_block.begin(), t_block.end());  // T = T(1) | T(2) | T(3) | ... | T(N)
            offset += t_block.size();
        }
        okm.resize(dlen);  // OKM = first L octets of T
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
