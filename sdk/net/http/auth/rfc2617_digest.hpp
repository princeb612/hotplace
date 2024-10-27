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

#ifndef __HOTPLACE_SDK_NET_HTTP_RFC2617_DIGEST__
#define __HOTPLACE_SDK_NET_HTTP_RFC2617_DIGEST__

#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/net/types.hpp>

namespace hotplace {
namespace net {

class rfc2617_digest {
   public:
    rfc2617_digest();
    rfc2617_digest& add(const char* data);
    rfc2617_digest& add(const std::string& data);
    rfc2617_digest& add(const basic_stream& data);
    rfc2617_digest& operator<<(const char* data);
    rfc2617_digest& operator<<(const std::string& data);
    rfc2617_digest& operator<<(const basic_stream& data);
    rfc2617_digest& digest(const std::string& algorithm);
    std::string get();
    std::string get_sequence();
    rfc2617_digest& clear();

   private:
    basic_stream _sequence;
    basic_stream _stream;
};

}  // namespace net
}  // namespace hotplace

#endif
