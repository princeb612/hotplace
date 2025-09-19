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

#ifndef __HOTPLACE_SDK_NET_TLS_QUIC_QUIC__
#define __HOTPLACE_SDK_NET_TLS_QUIC_QUIC__

#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/quic/types.hpp>
#include <hotplace/sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   an integer value using the variable-length encoding
 * @param   const byte_t* stream [in]
 * @param   size_t size [in]
 * @param   size_t& pos [inout]
 * @param   uint64& value [out]
 * @remarks RFC 9000
 *            16.  Variable-Length Integer Encoding
 *              Table 4: Summary of Integer Encodings
 *            17.1.  Packet Number Encoding and Decoding
 *            A.1.  Sample Variable-Length Integer Decoding
 *              Figure 45: Sample Variable-Length Integer Decoding Algorithm
 */
return_t quic_read_vle_int(const byte_t* stream, size_t size, size_t& pos, uint64& value);
/**
 * @brief   an integer value using the variable-length encoding
 * @param   uint64 value [in]
 * @param   binary_t& bin [out]
 * @remarks RFC 9000
 *            16.  Variable-Length Integer Encoding
 *              Table 4: Summary of Integer Encodings
 *            17.1.  Packet Number Encoding and Decoding
 *            A.1.  Sample Variable-Length Integer Decoding
 *              Figure 45: Sample Variable-Length Integer Decoding Algorithm
 */
return_t quic_write_vle_int(uint64 value, binary_t& bin);
/**
 * @brief   enforce prefix (1..3)
 * @remarks
 *          quic_write_vle_int(23, bin);    // 0x17
 *          quic_write_vle_int(23, 2, bin); // 0x0417
 */
return_t quic_write_vle_int(uint64 value, uint8 prefix, binary_t& bin);

return_t quic_length_vle_int(uint64 value, uint8& length);
uint8 quic_length_vle_int(uint64 value);

/**
 * @brief   RFC 9000
 *            17.1.  Packet Number Encoding and Decoding
 *            A.2.  Sample Packet Number Encoding Algorithm
 *              Figure 46: Sample Packet Number Encoding Algorithm
 */
return_t encode_packet_number(uint64 full_pn, uint64 largest_acked, uint64& represent, uint8& nbits);

/**
 * @brief   RFC 9000
 *            17.1.  Packet Number Encoding and Decoding
 *            A.3.  Sample Packet Number Decoding Algorithm
 *              Figure 47: Sample Packet Number Decoding Algorithm
 */
return_t decode_packet_number(uint64 largest_pn, uint64 truncated_pn, uint8 pn_nbits, uint64& value);

}  // namespace net
}  // namespace hotplace

#endif
