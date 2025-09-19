/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2005.07.07   Soo Han, Kim        implemented using windows sdk
 * 2012.03.08   Soo Han, Kim        refactor (codename.merlin)
 * 2017.07.06   Soo Han, Kim        implemented using openssl (codename.grape)
 * 2023.02.06   Soo Han, Kim        refactor plugin_pe, plugin_msi, plugin_cabinet (codename.unicorn)
 * 2023.08.27   Soo Han, Kim        refactor (codename.hotplace)
 */

#ifndef __HOTPLACE_SDK_CRYPTO_AUTHENTICODE_AUTHENTICODEPLUGIN__
#define __HOTPLACE_SDK_CRYPTO_AUTHENTICODE_AUTHENTICODEPLUGIN__

#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/crypto/authenticode/types.hpp>

namespace hotplace {
namespace crypto {

/**
 * @brief abstract engine class for PE, MSI, Cabinet
 */
class authenticode_plugin {
   public:
    authenticode_plugin();
    virtual ~authenticode_plugin();

    /**
     * @brief read a PKCS7 context
     * @param void* file_stream* filestream [in]
     * @param binary_t& bin [out]
     * @return errorcode_t::not_available
     */
    virtual return_t extract(file_stream* filestream, binary_t& bin);

    virtual int addref();
    virtual int release();

    /**
     * @brief is kind of
     * @return false
     */
    virtual bool is_kind_of(file_stream* filestream) = 0;
    /**
     * @brief extract IMAGE_DIRECTORY_ENTRY_SECURITY(4) data
     * @param file_stream* filestream [in]
     * @param binary_t& data [out]
     * @return errorcode_t::not_supported
     */
    virtual return_t read_authenticode(file_stream* filestream, binary_t& data) = 0;
    /**
     * @brief write directory entry data
     * @param file_stream* filestream [in]
     * @param binary_t data [in]
     * @return errorcode_t::not_supported
     */
    virtual return_t write_authenticode(file_stream* filestream, binary_t data) = 0;

    /**
     * @brief digest
     * @param file_stream* filestream [in]
     * @param const char* algorithm [in]
     * @param binary_t& data [out]
     */
    virtual return_t digest(file_stream* filestream, const char* algorithm, binary_t& data) = 0;

    /**
     * @brief is a signed separated file
     */
    virtual bool separated() = 0;
    /**
     * @brief find a separated file list
     * @param std::list<std::string> pathlist [in]
     * @param std::string filepathname_not_signed [in]
     * @param std::list<std::string>& filelist [out] signed files
     */
    virtual return_t find_if_separated(std::string filepathname_not_signed, std::list<std::string> pathlist, std::list<std::string>& filelist) = 0;
    /**
     * @brief verify a separated file
     * @param std::string file_not_signed [in] not signed file
     * @param std::string file_signed [in] signed file
     * @param uint32* result [out]
     */
    virtual return_t verify_if_separated(std::string file_not_signed, std::string file_signed, uint32* result) = 0;

    /**
     * @return authenticode_engine_id_t
     */
    virtual authenticode_engine_id_t id() = 0;

   private:
    t_shared_reference<authenticode_plugin> _shared;
};

}  // namespace crypto
}  // namespace hotplace

#endif
