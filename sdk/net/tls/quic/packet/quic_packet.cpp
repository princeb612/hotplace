/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/string/string.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/quic/packet/quic_packet.hpp>
#include <sdk/net/tls/quic/packet/quic_packet_builder.hpp>
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/quic/quic_encoded.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_hdr[] = "hdr";
constexpr char constexpr_longheader[] = "longheader";
constexpr char constexpr_version[] = "version";
constexpr char constexpr_dcid[] = "dcid";
constexpr char constexpr_scid[] = "scid";
constexpr char constexpr_dcid_len[] = "dcid len";
constexpr char constexpr_scid_len[] = "scid len";

quic_packet::quic_packet(tls_session* session) : _type(0), _session(nullptr), _ht(0), _version(1), _pn(0), _frames(nullptr) {
    set_session(session);
    set_version();
    _shared.make_share(this);

    _frames = new quic_frames(this);
}

quic_packet::quic_packet(quic_packet_t type, tls_session* session) : _type(type), _session(nullptr), _ht(0), _version(1), _pn(0), _frames(nullptr) {
    bool is_longheader = true;
    set_session(session);
    set_version();
    set_type(type, _ht, is_longheader);
    _shared.make_share(this);

    _frames = new quic_frames(this);
}

quic_packet::quic_packet(const quic_packet& rhs)
    : _type(rhs._type), _session(nullptr), _ht(rhs._ht), _version(rhs._version), _dcid(rhs._dcid), _scid(rhs._scid), _pn(rhs._pn), _frames(nullptr) {
    set_session(rhs._session);
    set_version();
    _shared.make_share(this);

    _frames = new quic_frames(this);
}

quic_packet::~quic_packet() {
    delete _frames;

    if (_session) {
        _session->release();
    }
}

uint8 quic_packet::get_type() { return _type; }

void quic_packet::get_type(uint8 hdr, uint8& type, bool& is_longheader) { quic_packet_get_type(_version, hdr, type, is_longheader); }

void quic_packet::set_type(uint8 type, uint8& hdr, bool& is_longheader) {
    quic_packet_set_type(session_type_quic == get_session()->get_type() ? quic_1 : quic_2, type, hdr, is_longheader);
}

quic_packet& quic_packet::set_version() {
    auto session = get_session();
    uint32 session_type = session->get_type();
    if (session_type_quic == session_type) {
        _version = quic_1;
    } else {
        _version = quic_2;
    }
    return *this;
}

uint32 quic_packet::get_version() { return _version; }

quic_packet& quic_packet::set_dcid(const binary& cid) {
    _dcid = cid;
    return *this;
}

quic_packet& quic_packet::set_scid(const binary& cid) {
    _scid = cid;
    return *this;
}

const binary_t& quic_packet::get_dcid() { return _dcid; }

const binary_t& quic_packet::get_scid() { return _scid; }

return_t quic_packet::read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) { return errorcode_t::success; }

return_t quic_packet::read(tls_direction_t dir, const binary_t& bin, size_t& pos) { return read(dir, &bin[0], bin.size(), pos); }

return_t quic_packet::write(tls_direction_t dir, binary_t& packet) {
    return_t ret = errorcode_t::success;
    __try2 {
        binary_t header;
        binary_t ciphertext;
        binary_t tag;

        packet.clear();

        ret = write(dir, header, ciphertext, tag);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        binary_append(packet, header);
        binary_append(packet, ciphertext);
        binary_append(packet, tag);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t quic_packet::write(tls_direction_t dir, binary_t& header, binary_t& ciphertext, binary_t& tag) { return errorcode_t::success; }

return_t quic_packet::write_header(binary_t& header) { return write(from_any, header); }

return_t quic_packet::read_common_header(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if ((size < 6) || (size < pos)) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            dbs.println("# QUIC packet (size %zi)", size);
            trace_debug_event(trace_category_net, trace_event_quic_packet, &dbs);
        }
#endif

        auto session = get_session();
        auto& protection = session->get_tls_protection();
        auto& secrets = protection.get_secrets();

        byte_t hdr = stream[pos];
        bool is_longheader = true;
        get_type(hdr, _type, is_longheader);

        // RFC 9000
        //   17.2.  Long Header Packets
        //   17.3.  Short Header Packets

        payload pl;
        pl << new payload_member(uint8(0), constexpr_hdr)                                   //
           << new payload_member(uint32(0), true, constexpr_version, constexpr_longheader)  //
           << new payload_member(uint8(0), constexpr_dcid_len, constexpr_longheader)        //
           << new payload_member(binary_t(), constexpr_dcid)                                //
           << new payload_member(uint8(0), constexpr_scid_len, constexpr_longheader)        //
           << new payload_member(binary_t(), constexpr_scid, constexpr_longheader);         //
        if (is_longheader) {
            pl.set_reference_value(constexpr_dcid, constexpr_dcid_len);
            pl.set_reference_value(constexpr_scid, constexpr_scid_len);
        } else {
            // RFC 9000 5.1.  Connection ID
            // Packets with short headers (Section 17.3) only include the Destination Connection ID and omit the explicit length.
            auto size_dcid = 0;
            if (from_client == dir) {
                size_dcid = secrets.get(tls_context_server_cid).size();
            } else if (from_server == dir) {
                size_dcid = secrets.get(tls_context_client_cid).size();
            }
            pl.reserve(constexpr_dcid, size_dcid);
        }
        pl.set_group(constexpr_longheader, is_longheader);  // see get_type

        pl.read(stream, size, pos);

        _ht = hdr;
        _version = pl.t_value_of<uint32>(constexpr_version);
        pl.get_binary(constexpr_dcid, _dcid);
        pl.get_binary(constexpr_scid, _scid);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t quic_packet::write_common_header(binary_t& header) {
    return_t ret = errorcode_t::success;

    uint8 hdr = 0;
    bool is_longheader = true;

    if (_ht) {
        uint8 pty = 0;
        get_type(_ht, pty, is_longheader);
    } else {
        set_type(_type, _ht, is_longheader);
    }

    hdr = _ht;
    switch (_type) {
        /**
         * RFC 9001 17.2.5.  Retry Packet
         * The value in the Unused field is set to an arbitrary value by the server; a client MUST ignore these bits.
         */
        case quic_packet_type_retry:
            hdr |= 0xf;
            break;
        default:
            break;
    }

    payload pl;
    pl << new payload_member(hdr, constexpr_hdr)                                             //
       << new payload_member(_version, true, constexpr_version, constexpr_longheader)        //
       << new payload_member(uint8(_dcid.size()), constexpr_dcid_len, constexpr_longheader)  //
       << new payload_member(_dcid, constexpr_dcid)                                          //
       << new payload_member(uint8(_scid.size()), constexpr_scid_len, constexpr_longheader)  //
       << new payload_member(_scid, constexpr_scid, constexpr_longheader);                   //
    pl.set_group(constexpr_longheader, is_longheader);
    pl.write(header);

    return ret;
}

void quic_packet::dump() {
#if defined DEBUG
    if (istraceable(trace_category_net)) {
        basic_stream dbs;

        tls_advisor* tlsadvisor = tls_advisor::get_instance();

        dbs.println("- quic packet %s", tlsadvisor->quic_packet_type_string(get_type()).c_str());
        dbs.println(" > version %08x", get_version());
        dbs.println(" > destination connection id %s", base16_encode(_dcid).c_str());
        // dump_memory(_dcid, &dbs, 16, 3, 0x0, dump_memory_flag_t::dump_notrunc);
        switch (get_type()) {
            // long header
            case quic_packet_type_version_negotiation:
            case quic_packet_type_initial:
            case quic_packet_type_0_rtt:
            case quic_packet_type_handshake:
            case quic_packet_type_retry:
                dbs.println(" > source connection id %s", base16_encode(_scid).c_str());
                // dump_memory(_scid, &dbs, 16, 3, 0x0, dump_memory_flag_t::dump_notrunc);
                break;
            // short header
            case quic_packet_type_1_rtt:
                break;
        }
        switch (get_type()) {
            case quic_packet_type_initial:
            case quic_packet_type_0_rtt:
            case quic_packet_type_handshake:
            case quic_packet_type_1_rtt:
                dbs.println(" > packet number length %i", get_pn_length());
                break;
        }
        trace_debug_event(trace_category_net, trace_event_quic_packet, &dbs);
    }
#endif
}

return_t quic_packet::header_protect(tls_direction_t dir, const binary_t& bin_ciphertext, protection_space_t space, uint8 hdr, uint8 pn_length,
                                     binary_t& bin_pn, binary_t& bin_protected_header) {
    return_t ret = errorcode_t::success;
    __try2 {
#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            dbs.println(" > packet number %s", base16_encode(bin_pn).c_str());
            dbs.println(" > packet number length %i", pn_length);
            trace_debug_event(trace_category_net, trace_event_quic_packet, &dbs);
        }
#endif

        auto session = get_session();
        auto& protection = session->get_tls_protection();

        if ((pn_length > 4) || bin_protected_header.empty()) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto adj = 4 - pn_length;
        binary_append(bin_pn, &bin_ciphertext[0], adj);

        // calcurate mask
        binary_t bin_mask;
        ret = protection.protection_mask(session, dir, &bin_ciphertext[adj], bin_ciphertext.size(), bin_mask, 5, space);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        if (quic_packet_field_hf & hdr) {
            hdr ^= bin_mask[0] & 0x0f;
        } else {
            hdr ^= bin_mask[0] & 0x1f;
        }
        memxor(&bin_pn[0], &bin_mask[1], 4);

        // encode packet length
        bin_protected_header[0] = hdr;
        bin_pn.resize(pn_length);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t quic_packet::header_unprotect(tls_direction_t dir, const byte_t* stream, size_t size, protection_space_t space, uint8& hdr, uint32& pn,
                                       binary_t& bin_payload) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto& protection = session->get_tls_protection();

        // protection mask
        binary_t bin_mask;
        ret = protection.protection_mask(session, dir, stream, size, bin_mask, 5, space);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        uint8 hdr_backup = hdr;

        // unprotect ht
        if (quic_packet_field_hf & hdr) {
            hdr ^= (bin_mask[0] & 0x0f);
        } else {
            hdr ^= (bin_mask[0] & 0x1f);
        }
        // unprotect pn
        auto pn_length = get_pn_length(hdr);

        // RFC 9001 5.4.2.  Header Protection Sample
        // Packet Number Length = 2
        //   ... | PN1 PN2 | PL1 PL2 PL3 PL4 ...
        //                 \- pnpad
        // Packet Number Length = 1
        //   ... | PN1 | PL1 PL2 PL3 PL4 PL5 ...
        //              \ pnpad
        // stream
        //   ... | PN1 PN2 PN3 PN4 | PL1 PL2 ...
        binary_t bin_pn;
        binary_append(bin_pn, &_payload[0], 4);
        memxor(&bin_pn[0], &bin_mask[1], 4);
        bin_pn.resize(pn_length);
        pn = t_binary_to_integer<uint32>(bin_pn);

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            dbs.println(" > protected   packet header byte 0x%02x", hdr_backup);
            dbs.println(" > unprotected packet header byte 0x%02x", hdr);
            dbs.println(" > packet number length %i", pn_length);

            binary_t bin_protected_pn;
            binary_append(bin_protected_pn, &bin_payload[0], pn_length);
            uint32 protected_pn = t_binary_to_integer<uint32>(bin_protected_pn);

            dbs.println(" > protected   packet number 0x%08x", protected_pn);
            dbs.println(" > unprotected packet number 0x%08x (%08i)", pn, pn);

            trace_debug_event(trace_category_net, trace_event_quic_packet, &dbs);
        }
#endif

        bin_payload.erase(bin_payload.begin(), bin_payload.begin() + pn_length);

        session->get_session_info(dir).set_recordno(pn, space);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

void quic_packet::set_pn(uint32 pn, uint8 len) {
    switch (get_type()) {
        case quic_packet_type_initial:
        case quic_packet_type_0_rtt:
        case quic_packet_type_handshake:
        case quic_packet_type_1_rtt: {
            uint8 elen = (len > 4) ? 4 : len;
            uint8 mlen = 1;
            if (pn > 0x00ffffff) {
                mlen = 4;
            } else if (pn > 0x0000ffff) {
                mlen = 3;
            } else if (pn > 0x000000ff) {
                mlen = 2;
            }
            if (elen > mlen) {
                mlen = elen;
            }
            uint8 l = (mlen - 1) & 0x03;
            _ht = (_ht & 0xfc) | l;
            _pn = pn;
        } break;
        default:
            break;
    }
}

uint8 quic_packet::get_pn_length() { return get_pn_length(_ht); }

uint8 quic_packet::get_pn_length(uint8 ht) {
    // RFC 9001 5.4.1.  Header Protection Application
    uint8 len = 0;
    switch (get_type()) {
        case quic_packet_type_initial:
        case quic_packet_type_0_rtt:
        case quic_packet_type_handshake:
        case quic_packet_type_1_rtt:
            len = (ht & 0x03) + 1;
            break;
        default:
            break;
    }
    return len;
}

uint32 quic_packet::get_pn() { return _pn; }

quic_frames& quic_packet::get_quic_frames() { return *_frames; }

quic_packet& quic_packet::operator<<(quic_frame* frame) {
    get_quic_frames() << frame;
    return *this;
}

quic_packet& quic_packet::set_payload(const binary_t& payload) {
    _payload = payload;
    return *this;
}

quic_packet& quic_packet::set_payload(const byte_t* stream, size_t size) {
    _payload.clear();
    binary_append(_payload, stream, size);
    return *this;
}

const binary_t& quic_packet::get_payload() { return _payload; }

tls_session* quic_packet::get_session() { return _session; }

void quic_packet::set_session(tls_session* session) {
    if (_session) {
        _session->release();
        _session = nullptr;
    }
    if (session) {
        session->addref();
        _session = session;
    }
}

void quic_packet::addref() { _shared.addref(); }

void quic_packet::release() { _shared.delref(); }

}  // namespace net
}  // namespace hotplace
