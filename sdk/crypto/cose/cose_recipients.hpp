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

#ifndef __HOTPLACE_SDK_CRYPTO_COSE_COSERECIPIENTS__
#define __HOTPLACE_SDK_CRYPTO_COSE_COSERECIPIENTS__

#include <hotplace/sdk/crypto/basic/types.hpp>
#include <hotplace/sdk/crypto/cose/types.hpp>
#include <hotplace/sdk/io/cbor/cbor.hpp>

namespace hotplace {
namespace crypto {

/**
 * @brief recipients, signatures
 */
class cose_recipients {
    friend class cose_composer;
    friend class cose_data;
    friend class cose_recipient;

   public:
    cose_recipients();
    virtual ~cose_recipients();

    /**
     * @brief add
     */
    cose_recipient& add(cose_recipient* recipient);
    /**
     * @brief clear
     */
    cose_recipients& clear();

    bool empty();
    size_t size();
    cose_recipient* operator[](size_t index);

    virtual cbor_array* cbor();

    return_t finditem(int key, int& value, int scope = cose_scope_layer);
    return_t finditem(int key, std::string& value, int scope = cose_scope_layer);
    return_t finditem(int key, binary_t& value, int scope = cose_scope_layer);

   protected:
    void for_each(void (*for_each_handler)(cose_recipient*, void* userdata), void* userdata);
    cose_recipients& set_upperlayer(cose_recipient* layer);
    cose_recipient* get_upperlayer();
    std::list<cose_recipient*>& get_recipients();
    const std::list<cose_recipient*>& get_recipients() const;

   private:
    std::list<cose_recipient*> _recipients;
    cose_recipient* _upperlayer;
};

}  // namespace crypto
}  // namespace hotplace

#endif
