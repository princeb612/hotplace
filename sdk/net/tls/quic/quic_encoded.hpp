/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * reference
 *  https://github.com/martinduke/quic-test-vector
 *  https://quic.xargs.org/
 *
 * studying...
 *
 * RFC 9000 QUIC: A UDP-Based Multiplexed and Secure Transport
 * RFC 9001 Using TLS to Secure QUIC
 *
 * OpenSSL 3.2 and later features support for the QUIC transport protocol.
 * Currently, only client connectivity is supported.
 * This man page describes the usage of QUIC client functionality for both existing and new applications.
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_QUIC_QUICENCODED__
#define __HOTPLACE_SDK_NET_TLS_QUIC_QUICENCODED__

#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/quic/types.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   QUIC variable length integer encoding
 * @sa      payload_member
 * @remarks
 *          sketch
 *          // Token Length (i),
 *          // Token (..),
 *          // 05 74 6F 6B 65 6E -- -- -- -- -- -- -- -- -- -- | .token
 *
 *          // payload set_reference_value interface
 *          payload pl1;
 *          binary_t bin1;
 *          pl1 << new payload_member(new quic_encoded(5)) << new payload_member("token");
 *          pl1.write(bin1);
 *
 *          payload pl2;
 *          binary_t bin2;
 *          pl2 << new payload_member(new quic_encoded(int(0)), "len") << new payload_member(binary_t(), "token");
 *          pl2.set_reference_value("token", "len");  // length of "token" is value of "len"
 *          pl2.read(bin1);
 *          pl2.write(bin2);
 *
 *          // simple
 *          payload p3;
 *          binary_t bin3;
 *          pl3 << new payload_member(new quic_encoded("token"));
 *          pl3.write(bin3);
 *
 *          payload pl4;
 *          binary_t bin4;
 *          pl4 << new payload_member(new quic_encoded);
 *          pl4.read(bin3);
 *          pl4.write(bin4);
 */
class quic_encoded : public payload_encoded {
   public:
    quic_encoded();
    quic_encoded(const quic_encoded& rhs);
    quic_encoded(quic_encoded&& rhs);
    /**
     * @brief   integers in the range 0 to 2^62-1
     */
    quic_encoded(uint64 data);
    quic_encoded(uint64 data, uint8 prefix);
    /**
     * @brief   integer + data
     */
    quic_encoded(const char* data);
    quic_encoded(const std::string& data);
    quic_encoded(const binary_t& data);

    quic_encoded& set(const char* data);
    quic_encoded& set(const std::string& data);
    quic_encoded& set(const binary_t& data);

    virtual ~quic_encoded();

    virtual size_t lsize();  // length size
    virtual size_t value();
    virtual const byte_t* data();
    virtual void write(binary_t& target);

    virtual size_t lsize(const byte_t* stream, size_t size);
    virtual size_t value(const byte_t* stream, size_t size);
    virtual return_t read(const byte_t* stream, size_t size, size_t& pos);

    virtual variant& get_variant();

   protected:
   private:
    bool _datalink;
    uint64 _value;
    uint8 _sizeof_value;
    variant _data;
};

}  // namespace net
}  // namespace hotplace

#endif
