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

#ifndef __HOTPLACE_SDK_CRYPTO_AUTHENTICODE_AUTHENTICODEPLUGINPE__
#define __HOTPLACE_SDK_CRYPTO_AUTHENTICODE_AUTHENTICODEPLUGINPE__

#include <hotplace/sdk/crypto/authenticode/authenticode_plugin.hpp>

namespace hotplace {
namespace crypto {

/**
 * @brief Windows PE authenticode
 */
class authenticode_plugin_pe : public authenticode_plugin {
   public:
    authenticode_plugin_pe();
    virtual ~authenticode_plugin_pe();

    /**
     * @brief is kind of
     * @param file_stream* filestream [in]
     */
    virtual bool is_kind_of(file_stream* filestream);
    /**
     * @brief extract IMAGE_DIRECTORY_ENTRY_SECURITY(4) data
     * @param file_stream* filestream [in]
     * @param binary_t& data [out]
     * @return error code (see error.hpp)
     */
    virtual return_t read_authenticode(file_stream* filestream, binary_t& data);
    /**
     * @brief where is the authenticode located at ?
     * @param file_stream* filestream [in]
     * @param size_t& begin [out]
     * @param size_t& size [out]
     * @return error code (see error.hpp)
     */
    return_t read_authenticode(file_stream* filestream, size_t& begin, size_t& size);
    /**
     * @brief write directory entry data
     * @param file_stream* filestream [in]
     * @param binary_t data [in]
     * @return error code (see error.hpp)
     */
    virtual return_t write_authenticode(file_stream* filestream, binary_t data);

    /**
     * @brief calcurate hash
     * @param file_stream* filestream [in]
     * @parm const char* algorithm [in] "sha1", ...
     * @param binary_t& output [out]
     */
    virtual return_t digest(file_stream* filestream, const char* algorithm, binary_t& output);

    /* separated authenticode */

    /**
     * @brief is a signed separated file
     */
    virtual bool separated();
    /**
     * @brief find a separated file list
     * @param std::list<std::string> pathlist [in]
     * @param std::string filepathname_not_signed [in]
     * @param std::list<std::string>& filelist [out] signed files
     */
    virtual return_t find_if_separated(std::string filepathname_not_signed, std::list<std::string> pathlist, std::list<std::string>& filelist);
    /**
     * @brief verify a separated file
     * @param std::string file_not_signed [in] not signed file
     * @param std::string file_signed [in] signed file
     * @param uint32* result [out]
     */
    virtual return_t verify_if_separated(std::string file_not_signed, std::string file_signed, uint32* result);
    /**
     * @brief extract PE checksum
     * @param file_stream* filestream [in]
     * @param uint32* out_checksum_value [out]
     * @return error code (see error.hpp)
     */
    return_t read_checksum(file_stream* filestream, uint32* out_checksum_value);
    /**
     * @brief update and extract PE checksum
     * @param file_stream* filestream [in]
     * @param uint32* out_checksum_value [out]
     * @return error code (see error.hpp)
     */
    return_t update_checksum(file_stream* filestream, uint32* out_checksum_value);
    return_t calc_checksum(file_stream* filestream, uint32* out_checksum_value);

    /**
     * @return authenticode_engine_id_t
     */
    virtual authenticode_engine_id_t id();
};

}  // namespace crypto
}  // namespace hotplace

#endif
