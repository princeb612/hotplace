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

#ifndef __HOTPLACE_SDK_NET_QUIC__
#define __HOTPLACE_SDK_NET_QUIC__

#include <sdk/net/types.hpp>

namespace hotplace {
namespace net {

// RFC 9000 QUIC: A UDP-Based Multiplexed and Secure Transport
// RFC 9001 Using TLS to Secure QUIC

// studying...

// OpenSSL 3.2 and later features support for the QUIC transport protocol.
// Currently, only client connectivity is supported.
// This man page describes the usage of QUIC client functionality for both existing and new applications.

// RFC 9000
// 17.  Packet Formats
// 17.2.  Long Header Packets
//  Figure 13: Long Header Packet Format
//  Table 5: Long Header Packet Types
// 17.2.1.  Version Negotiation Packet
//  Figure 14: Version Negotiation Packet
// 17.2.2.  Initial Packet
//  Figure 15: Initial Packet
// 17.2.3.  0-RTT
//  Figure 16: 0-RTT Packet
// 17.2.4.  Handshake Packet
//  Figure 17: Handshake Protected Packet
// 17.2.5.  Retry Packet
//  Figure 18: Retry Packet
// 17.3.1.  1-RTT Packet
//  Figure 19: 1-RTT Packet
// 18.  Transport Parameter Encoding
//  Figure 20: Sequence of Transport Parameters
//  Figure 21: Transport Parameter Encoding
// 18.2.  Transport Parameter Definitions
//  Figure 22: Preferred Address Format
// 19.  Frame Types and Formats
// 19.1.  PADDING Frames
//  Figure 23: PADDING Frame Format
// 19.2.  PING Frames
//  Figure 24: PING Frame Format
// 19.3.  ACK Frames
//  Figure 25: ACK Frame Format
// 19.3.1.  ACK Ranges
//  Figure 26: ACK Ranges
// 19.3.2.  ECN Counts
//  Figure 27: ECN Count Format
// 19.4.  RESET_STREAM Frames
//  Figure 28: RESET_STREAM Frame Format
// 19.5.  STOP_SENDING Frames
//  Figure 29: STOP_SENDING Frame Format
// 19.6.  CRYPTO Frames
//  Figure 30: CRYPTO Frame Format
// 19.7.  NEW_TOKEN Frames
//  Figure 31: NEW_TOKEN Frame Format
// 19.8.  STREAM Frames
//  Figure 32: STREAM Frame Format
// 19.9.  MAX_DATA Frames
//  Figure 33: MAX_DATA Frame Format
// 19.10.  MAX_STREAM_DATA Frames
//  Figure 34: MAX_STREAM_DATA Frame Format
// 19.11.  MAX_STREAMS Frames
//  Figure 35: MAX_STREAMS Frame Format
// 19.12.  DATA_BLOCKED Frames
//  Figure 36: DATA_BLOCKED Frame Format
// 19.13.  STREAM_DATA_BLOCKED Frames
//  Figure 37: STREAM_DATA_BLOCKED Frame Format
// 19.14.  STREAMS_BLOCKED Frames
//  Figure 38: STREAMS_BLOCKED Frame Format
// 19.15.  NEW_CONNECTION_ID Frames
//  Figure 39: NEW_CONNECTION_ID Frame Format
// 19.16.  RETIRE_CONNECTION_ID Frames
//  Figure 40: RETIRE_CONNECTION_ID Frame Format
// 19.17.  PATH_CHALLENGE Frames
//  Figure 41: PATH_CHALLENGE Frame Format
// 19.18.  PATH_RESPONSE Frames
//  Figure 42: PATH_RESPONSE Frame Format
// 19.19.  CONNECTION_CLOSE Frames
//  Figure 43: CONNECTION_CLOSE Frame Format
// 19.20.  HANDSHAKE_DONE Frames
//  Figure 44: HANDSHAKE_DONE Frame Format

}  // namespace net
}  // namespace hotplace

#endif
