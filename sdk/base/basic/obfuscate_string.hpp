/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *          obfuscate string at runtime
 *          use constexpr_obf to obfuscate a string at compile time (c++14 required)
 *
 * Revision History
 * Date         Name                Description
 * 2014.09.03   Soo Han, Kim        implemented (codename.merlin)
 * 2015.04.22   Soo Han, Kim        random factor (codename.merlin)
 * 2023.08.28   Soo Han, Kim        refactor
 */

#ifndef __HOTPLACE_SDK_BASE_BASIC_OBFUSCATESTRING__
#define __HOTPLACE_SDK_BASE_BASIC_OBFUSCATESTRING__

#include <sdk/base/stream/basic_stream.hpp>
#include <string>

namespace hotplace {

/**
 * @brief   obfuscate
 * @see     constexpr_obf
 * @example
 *      obfuscate_string obf;
 *      {
 *          char passwd = { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd', 0 };
 *          obf << passwd; // obf obfuscated
 *      }
 *      {
 *          std::string passwd;
 *          passwd << obf; // passwd readable, obf still obfuscated
 *      }
 *
 *      // see also
 *      #if __cplusplus >= 201402L    // c++14
 *      constexpr auto obf = constexpr_obf <8, 0x38>("password"); // compile time
 *      std::string passwd = obf.load_string ();
 *      #endif
 *
 */
class obfuscate_string {
   public:
    obfuscate_string();
    obfuscate_string(const char* source);
    obfuscate_string(std::string& source);
    obfuscate_string(basic_stream& source);
    ~obfuscate_string();

    /**
     * @brief   assign
     * @param   const char* source [in]
     * @param   size_t size [in]
     * @return  obfuscate_string&
     */
    obfuscate_string& assign(const char* source, size_t size);
    /**
     * @brief   append
     * @param   const char* source [in]
     * @param   size_t size [in]
     * @return  obfuscate_string&
     */
    obfuscate_string& append(const char* source, size_t size);
    /**
     * @brief   size
     * @return  size_t
     */
    size_t size();
    /**
     * @brief   is empty
     * @return  bool
     */
    bool empty();
    /**
     * @brief   compare
     * @param   obfuscate_string& o [in]
     * @return  bool
     */
    bool compare(obfuscate_string& o);

    /**
     * @brief   assign
     * @param   const char* [in]
     * @return  obfuscate_string&
     */
    obfuscate_string& operator=(const char* source);
    /**
     * @brief   assign
     * @param   std::string& source [in]
     * @return  obfuscate_string&
     */
    obfuscate_string& operator=(std::string& source);
    /**
     * @brief   assign
     * @param   basic_stream& source [in]
     * @return  obfuscate_string&
     */
    obfuscate_string& operator=(basic_stream& source);
    /**
     * @brief   append
     * @param   const char* source [in]
     * @return  obfuscate_string&
     */
    obfuscate_string& operator+=(const char* source);
    /**
     * @brief   append
     * @param   std::string& source [in]
     * @return  obfuscate_string&
     */
    obfuscate_string& operator+=(std::string& source);
    /**
     * @brief   append
     * @param   basic_stream& source [in]
     * @return  obfuscate_string&
     */
    obfuscate_string& operator+=(basic_stream& source);
    /**
     * @brief   append
     * @param   const char* source [in]
     * @return  obfuscate_string&
     */
    obfuscate_string& operator<<(const char* source);
    /**
     * @brief   append
     * @param   std::string& source [in]
     * @return  obfuscate_string&
     */
    obfuscate_string& operator<<(std::string& source);
    /**
     * @brief   append
     * @param   basic_stream& source [in]
     * @return  obfuscate_string&
     */
    obfuscate_string& operator<<(basic_stream& source);

    /**
     * @brief   compare equal
     * @param   obfuscate_string& o [in]
     * @return  bool
     */
    bool operator==(obfuscate_string& o);
    /**
     * @brief   compre not equal
     * @param   obfuscate_string& o [in]
     * @return  bool
     */
    bool operator!=(obfuscate_string& o);

    /**
     * @brief   append
     * @param   std::string& lhs [out]
     * @param   const obfuscate_string& rhs [in]
     * @return  std::string&
     */
    friend std::string& operator<<(std::string& lhs, const obfuscate_string& rhs);
    /**
     * @brief   append
     * @param   std::string& lhs [out]
     * @param   const obfuscate_string& rhs [in]
     * @return  basic_stream&
     */
    friend basic_stream& operator<<(basic_stream& lhs, const obfuscate_string& rhs);
    /**
     * @brief   append
     * @param   binary_t& lhs [out]
     * @param   const obfuscate_string& rhs [in]
     * @return  binary_t&
     */
    friend binary_t& operator<<(binary_t& lhs, const obfuscate_string& rhs);

   protected:
    void startup();
    void cleanup();

   private:
    uint32 _flags;
    byte_t _factor;
    binary_t _contents;
};

}  // namespace hotplace

#endif
