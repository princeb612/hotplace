/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2014.09.03   Soo Han, Kim        implemented (merlin)
 * 2015.04.22   Soo Han, Kim        random factor (merlin)
 * 2023.08.28   Soo Han, Kim        refactor
 */

#ifndef __HOTPLACE_SDK_IO_BASIC_OBFUSCATESTRING__
#define __HOTPLACE_SDK_IO_BASIC_OBFUSCATESTRING__

#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/io/stream/bufferio.hpp>
#include <hotplace/sdk/io/stream/stream.hpp>
#include <hotplace/sdk/io/stream/string.hpp>
#include <string>

namespace hotplace {
namespace io {

/**
 * @brief   obfuscate
 * @example
 *      obfuscate_string obf;
 *      {
 *          char passwd = { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd', 0 };
 *          obf = passwd; // not readable
 *      }
 *      {
 *          std::string passwd;
 *          passwd = obf; // passwd readable, obf still not readble
 *      }
 */
class obfuscate_string
{
public:
    obfuscate_string ();
    obfuscate_string (const char* source);
    obfuscate_string (std::string& source);
    obfuscate_string (ansi_string& source);
    ~obfuscate_string ();

    obfuscate_string& assign (const char* source, size_t size);
    obfuscate_string& append (const char* source, size_t size);
    size_t size ();
    bool empty ();
    bool compare (obfuscate_string& o);

    /**
     * @brief   assign
     */
    obfuscate_string& operator = (const char* source);
    obfuscate_string& operator = (std::string source);
    obfuscate_string& operator = (ansi_string source);
    /**
     * @brief   append
     */
    obfuscate_string& operator += (const char* source);
    obfuscate_string& operator += (std::string& source);
    obfuscate_string& operator += (ansi_string& source);
    obfuscate_string& operator << (const char* source);
    obfuscate_string& operator << (std::string& source);
    obfuscate_string& operator << (ansi_string& source);

    /**
     * @brief   compare equal
     */
    bool operator == (obfuscate_string& o);
    /**
     * @brief   compre not equal
     */
    bool operator != (obfuscate_string& o);

    friend std::string& operator << (std::string& lhs, obfuscate_string& rhs);
    friend ansi_string& operator << (ansi_string& lhs, obfuscate_string& rhs);
    friend binary_t& operator << (binary_t& lhs, obfuscate_string& rhs);

protected:
    void init_if_necessary ();
    void finalize ();

private:
    uint32 _flags;
    byte_t _factor;
    binary_t _contents;
};

}
}  // namespace

#endif
