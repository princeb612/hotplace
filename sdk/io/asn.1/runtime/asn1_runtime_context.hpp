/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_runtime_context.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_RUNTIME_ASN1RUNTIMECONTEXT__
#define __HOTPLACE_SDK_IO_ASN1_RUNTIME_ASN1RUNTIMECONTEXT__

#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/io/asn.1/basic/types.hpp>

namespace hotplace {
namespace io {

class asn1_runtime_context {
   public:
    static asn1_runtime_context* get_instance();

    ~asn1_runtime_context();

    asn1_runtime_context(const asn1_runtime_context& other) = delete;
    asn1_runtime_context(asn1_runtime_context&& other) = delete;

    asn1_runtime_context& operator=(const asn1_runtime_context& other) = delete;
    asn1_runtime_context& operator=(asn1_runtime_context&& other) = delete;

    // name "<DEFAULT>" reserved
    /*
     * @brief   add
     */
    return_t add(asn1_runtime* runtime);
    /*
     * @brief   add
     */
    asn1_runtime* add(const std::string& name);
    /*
     * @brief   get
     * @return  runtime pointer if exists, otherwise nullptr
     */
    asn1_runtime* get(const std::string& name) const;
    /*
     * @brief   exist
     * @return  true if exists, otherwise false
     */
    bool exist(const std::string& name) const;
    /*
     * @brief   remove registered runtime by name
     * @remarks if the target for deletion is _current, it resets _current to _default
     * @return  true if exists, otherwise false
     */
    bool remove(const std::string& name);
    /*
     * @brief    default runtime
     */
    asn1_runtime* get_default();

    std::string temp_name() const;
    void sweep_temp();

   protected:
    asn1_runtime_context();

   private:
    static asn1_runtime_context _instance;

    mutable critical_section _lock;
    std::map<std::string, asn1_runtime*> _contexts;
    asn1_runtime* _default;
};

}  // namespace io
}  // namespace hotplace

#endif
