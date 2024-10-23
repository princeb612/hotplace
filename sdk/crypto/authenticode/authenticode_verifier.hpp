/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *      verification
 *        PKCS7 format verification
 *        contents hash verification
 *        CRL revocation verification (temporary disabled, file download)
 *        PE checksum
 *        signer
 *      msi, cabinet plugin excluded
 *
 * Revision History
 * Date         Name                Description
 * 2005.07.07   Soo Han, Kim        implemented using windows sdk
 * 2012.03.08   Soo Han, Kim        refactor (codename.merlin)
 * 2017.07.06   Soo Han, Kim        implemented using openssl (codename.grape)
 * 2023.02.06   Soo Han, Kim        refactor plugin_pe, plugin_msi, plugin_cabinet (codename.unicorn)
 * 2023.08.27   Soo Han, Kim        refactor (codename.hotplace)
 */

#ifndef __HOTPLACE_SDK_CRYPTO_AUTHENTICODE_VERIFIER__
#define __HOTPLACE_SDK_CRYPTO_AUTHENTICODE_VERIFIER__

#include <sdk/base/charset.hpp>
#include <sdk/base/error.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>
#include <sdk/crypto/authenticode/authenticode_plugin.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>

namespace hotplace {
namespace crypto {

class authenticode_plugin;
struct _authenticode_context_t;
typedef struct _authenticode_context_t authenticode_context_t;

enum authenticode_ctrl_t {
    set_proxy = 1,          // "http://127.0.0.1:3128/"
    set_proxy_user = 2,     // "user:password"
    set_gen_der = 3,        // generate DER (for test) int
    set_crl = 4,            // crl download (for test) int
    set_digicert_path = 5,  // path
    reset_digicert_path = 6,
    set_crl_path = 7,  // crl download path
};
enum authenticode_flag_t {
    flag_separated = 1,
};

/**
 * @brief verifier
 * @example
 *        openssl_startup(); // begin of application
 *        authenticode_verifier verifier;
 *        verifier.open(&handle, filepath);
 *        verifier.add_trusted_rootcert(handle, "trust.crt", nullptr);
 *        verifier.verify_file(handle, filepathname, result);
 *        verifier.close(handle);
 *        openssl_cleanup(); // end of application
 */
class authenticode_verifier {
   public:
    authenticode_verifier();
    ~authenticode_verifier();

    /**
     * @brief open
     * @param authenticode_context_t** handle [out]
     * @return error code (see error.hpp)
     * @remarks
     *      // check
     *      openssl_startup();
     *      // ...
     *      openssl_cleanup();
     */
    return_t open(authenticode_context_t** handle);
    /**
     * @brief set
     * @param authenticode_context_t* handle [in]
     * @param int option [in]
     * @param void* data [in]
     * @param size_t size [in]
     */
    return_t set(authenticode_context_t* handle, int option, void* data, size_t size);
    /**
     * @brief verify
     * @param authenticode_context_t* handle [in]
     * @param const char* name [in]
     * @param uint32 flags [in] reserved
     * @param uint32& result [out] reserved
     * @return error code (see error.hpp)
     */
    return_t verify(authenticode_context_t* handle, const char* file_name, uint32 flags, uint32& result, uint32* engine_id = nullptr);
    /**
     * @brief close
     * @param authenticode_context_t* handle [in]
     * @return error code (see error.hpp)
     */
    return_t close(authenticode_context_t* handle);
    /**
     * @brief add a trusted signer
     * @param authenticode_context_t* handle [in]
     * @parm const char* signer [in]
     * @return error code (see error.hpp)
     * @remarks
     *        if signer not added, verify fails X509_V_ERR_CERT_UNTRUSTED (27)
     */
    return_t add_trusted_signer(authenticode_context_t* handle, const char* signer);
    /**
     * @brief remove a trusted signer
     * @param authenticode_context_t* handle [in]
     * @parm const char* signer [in]
     * @return error code (see error.hpp)
     */
    return_t remove_trusted_signer(authenticode_context_t* handle, const char* signer);
    /**
     * @brief remove all trusted signer
     * @param authenticode_context_t* handle [in]
     * @return error code (see error.hpp)
     */
    return_t remove_all_trusted_signer(authenticode_context_t* handle);
    /**
     * @brief add trusted root certificate
     * @param authenticode_context_t* handle [in]
     * @param const char* file [inopt]
     * @param const char* path [inopt]
     * @return error code (see error.hpp)
     */
    return_t add_trusted_rootcert(authenticode_context_t* handle, const char* file, const char* path);
    /**
     * @brief add engine
     * @param authenticode_context_t* handle [in]
     * @param authenticode_plugin* engine
     * @return error code (see error.hpp)
     * @example
     *      engine = new AuthenticodeEngineImpl;
     *      ret = add_engine(handle, engine);
     *      if (errorcode_t::success != ret) {
     *          engine->release ();
     *      }
     */
    return_t add_engine(authenticode_context_t* handle, authenticode_plugin* engine);

   protected:
    /**
     * @brief verify pkcs7 der
     * @param authenticode_context_t* handle [in]
     * @param void* pkcs7 [in]
     * @param uint32 flags [in]
     * @param uint32& result [out]
     * @return error code (see error.hpp)
     */
    return_t verify_pkcs7(authenticode_context_t* handle, void* pkcs7, uint32 flags, uint32& result);

    return_t verify_separated(authenticode_context_t* handle, const char* file_name, uint32 flags, uint32& result);
    /**
     * @brief hash
     * @param const char* filename [in]
     * @param HASH_ALGORITHM algorithm [in]
     * @param std::string& hash [out]
     * @return error code (see error.hpp)
     */
    return_t hash(const char* filename, hash_algorithm_t algorithm, std::string& hash);

    /**
     * @brief load engines
     * @param authenticode_context_t* handle [in]
     */
    return_t load_engines(authenticode_context_t* handle);
    /**
     * @brief free engines
     * @param authenticode_context_t* handle [in]
     */
    return_t free_engines(authenticode_context_t* handle);
};

}  // namespace crypto
}  // namespace hotplace

#endif
