/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt_psk_binder.cpp
 * @author GPT
 * @desc   TLS 1.3 PSK binder vectors, transcript calculation, and client serialization tests.
 */

#include <algorithm>
#include <chrono>
#include <utility>

#include "testcase_gpt_common.hpp"

static void test_tls13_psk_binder_rfc8448_vector() {
    // Scenario under test: TLS 1.3 PSK binder SHA-256 and SHA-384 known-answer vectors.
    // Action: derive the RFC 8448 empty transcript hash.
    // Expected: match the RFC 8448 PSK binder known-answer value.
    _test_case.begin("TLS 1.3 PSK binder SHA-256 and SHA-384 known-answer vectors");

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls1_3);
    protection.set_cipher_suite(0x1301);

    const binary_t resumption_psk = base16_decode_rfc("9b2188e9b2fc6d64d71dc329900e20bb41915000f678aa839cbb797cb7d8332c");
    const binary_t binder_hash = base16_decode_rfc("63224b2e4573f2d3454ca84b9d009a04f6be9e05711a8396473aefa01e924a14");
    const binary_t expected_binder = base16_decode_rfc("3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d");

    openssl_digest digest;
    binary_t empty;
    binary_t empty_hash;
    return_t ret = digest.digest("sha256", empty, empty_hash);
    _test_case.test(ret, __FUNCTION__, "derive the RFC 8448 empty transcript hash");
    if (errorcode_t::success != ret) {
        return;
    }

    protection.get_secrets().assign(tls_secret_t::resumption_early, resumption_psk);
    protection.get_secrets().assign(tls_secret_t::empty_hash, empty_hash);

    binary_t binder;
    ret = protection.calc_psk_binder(&session, binder_hash, binder);
    _test_case.test(ret, __FUNCTION__, "calculate the RFC 8448 resumption PSK binder");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(expected_binder == binder, __FUNCTION__, "match the RFC 8448 PSK binder known-answer value");

    ret = protection.calc_psk(&session, binder_hash, expected_binder);
    _test_case.test(ret, __FUNCTION__, "validate the RFC 8448 PSK binder with the shared calculation");

    const std::array<size_t, 3> modified_offsets = {0, expected_binder.size() / 2, expected_binder.size() - 1};
    for (size_t offset : modified_offsets) {
        binary_t modified_binder = expected_binder;
        modified_binder[offset] ^= 0x01;
        ret = protection.calc_psk(&session, binder_hash, modified_binder);
        _test_case.assert(errorcode_t::mismatch == ret, __FUNCTION__, "reject a modified RFC 8448 PSK binder at every tested offset");
    }
    binary_t truncated_binder = expected_binder;
    truncated_binder.pop_back();
    ret = protection.calc_psk(&session, binder_hash, truncated_binder);
    _test_case.assert(errorcode_t::mismatch == ret, __FUNCTION__, "reject a truncated RFC 8448 PSK binder");

    // Independent SHA-384 binder vector. Deliberately leave the cached empty
    // hash as SHA-256 to ensure binder derivation selects the PSK suite hash.
    protection.set_cipher_suite(0x1302);
    protection.get_secrets().assign(tls_secret_t::resumption_early, binary_t(48, 0x44));
    const binary_t sha384_binder_hash(48, 0x55);
    const binary_t expected_sha384_binder = base16_decode_rfc("c105b0279bcfb161bd470c73a97a44eeded5a2f34f3c547daa7edb543c09748c0582837e63885ade298b948a3f034307");
    binary_t sha384_binder;
    ret = protection.calc_psk_binder(&session, sha384_binder_hash, sha384_binder);
    _test_case.test(ret, __FUNCTION__, "calculate a SHA-384 resumption PSK binder");
    if (errorcode_t::success == ret) {
        _test_case.assert(48 == sha384_binder.size(), __FUNCTION__, "produce a 48-byte SHA-384 binder");
        _test_case.assert(expected_sha384_binder == sha384_binder, __FUNCTION__, "match the independent SHA-384 binder vector");
        ret = protection.calc_psk(&session, sha384_binder_hash, expected_sha384_binder);
        _test_case.test(ret, __FUNCTION__, "validate the SHA-384 binder with the shared calculation");
    }

    binary_t wrong_sha384_hash(32, 0x55);
    ret = protection.calc_psk_binder(&session, wrong_sha384_hash, sha384_binder);
    _test_case.assert(errorcode_t::bad_format == ret, __FUNCTION__, "reject a transcript hash whose length does not match SHA-384");
    protection.get_secrets().assign(tls_secret_t::resumption_early, binary_t(32, 0x44));
    ret = protection.calc_psk_binder(&session, sha384_binder_hash, sha384_binder);
    _test_case.assert(errorcode_t::bad_format == ret, __FUNCTION__, "reject a PSK early secret whose length does not match SHA-384");
}

struct tls13_psk_binder_test_context {
    uint32 ticket_age_add;
    uint32 ticket_lifetime;
    binary_t ticket;
    binary_t resumption_psk;
    binary_t wire;
    size_t extension_block;
    size_t psk_offset;
    size_t psk_size;

    tls13_psk_binder_test_context()
        : ticket_age_add(0x50607080), ticket_lifetime(3600), ticket{0xaa, 0xbb, 0xcc}, resumption_psk(32, 0x11), extension_block(0), psk_offset(0), psk_size(0) {}
};

static void configure_tls13_psk_binder_resumption(tls_session& session, const tls13_psk_binder_test_context& context) {
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls1_3);
    protection.set_cipher_suite(0x1301);
    session.get_keyvalue().set(session_tls_version, tls1_3);
    session.update_session_status(session_status_server_finished);
    session.update_session_status(session_status_client_finished);
    session.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
    session.get_session_info(from_server).set_status(tls_handshake_type_t::finished);

    uint64 now_ms = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    auto& ticket_kv = session.get_session_info(from_server).get_keyvalue();
    ticket_kv.set(session_ticket_lifetime, context.ticket_lifetime);
    ticket_kv.set(session_ticket_age_add, context.ticket_age_add);
    ticket_kv.set(session_ticket_timestamp, now_ms - 25);
    protection.get_secrets().assign(tls_secret_t::new_session_ticket, context.ticket);
    protection.get_secrets().assign(tls_secret_t::resumption_early, context.resumption_psk);
    openssl_digest digest;
    binary_t empty;
    binary_t empty_hash;
    digest.digest("sha256", empty, empty_hash);
    protection.get_secrets().assign(tls_secret_t::empty_hash, empty_hash);
}

static void test_tls13_psk_binder_rejects_incomplete_offers(const char* function_name, const tls13_psk_binder_test_context& context) {
    // Scenario under test: incomplete and incorrectly ordered TLS 1.3 PSK offers.
    // Action: serialize ClientHello with missing psk_key_exchange_modes or a non-final pre_shared_key extension.
    // Expected: reject incomplete PSK offers without emitting malformed ClientHello bytes.
    tls_session missing_modes_client;
    configure_tls13_psk_binder_resumption(missing_modes_client, context);
    auto missing_modes_hello = new tls_handshake_client_hello(&missing_modes_client);
    missing_modes_hello->add_ciphersuite(0x1301);
    auto missing_modes_version = new tls_extension_client_supported_versions(missing_modes_hello);
    missing_modes_version->add(tls1_3);
    missing_modes_hello->get_extensions().add(missing_modes_version);
    missing_modes_hello->get_extensions().add(new tls_extension_client_psk(missing_modes_hello));

    tls_record_handshake missing_modes_record(&missing_modes_client);
    missing_modes_record << missing_modes_hello;
    binary_t missing_modes_wire;
    return_t missing_modes_ret = missing_modes_record.write(from_client, missing_modes_wire);
    _test_case.assert(errorcode_t::success != missing_modes_ret, function_name, "reject a PSK ClientHello without psk_key_exchange_modes");
    _test_case.assert(missing_modes_wire.empty(), function_name, "emit no ClientHello with an incomplete PSK offer");

    {
        tls_session non_final_client;
        configure_tls13_psk_binder_resumption(non_final_client, context);
        auto non_final_hello = new tls_handshake_client_hello(&non_final_client);
        non_final_hello->add_ciphersuite(0x1301);
        auto non_final_modes = new tls_extension_psk_key_exchange_modes(non_final_hello);
        non_final_modes->add(1);
        non_final_hello->get_extensions().add(non_final_modes);
        non_final_hello->get_extensions().add(new tls_extension_client_psk(non_final_hello));
        auto trailing_version = new tls_extension_client_supported_versions(non_final_hello);
        trailing_version->add(tls1_3);
        non_final_hello->get_extensions().add(trailing_version);

        tls_record_handshake non_final_record(&non_final_client);
        non_final_record << non_final_hello;
        binary_t non_final_wire;
        return_t non_final_ret = non_final_record.write(from_client, non_final_wire);
        _test_case.assert(errorcode_t::success != non_final_ret, function_name, "reject a ClientHello that places pre_shared_key before another extension");
        _test_case.assert(non_final_wire.empty(), function_name, "emit no ClientHello with a non-final pre_shared_key extension");
    }
}

static bool test_tls13_psk_binder_build_clienthello(const char* function_name, tls13_psk_binder_test_context& context) {
    // Scenario under test: TLS 1.3 ClientHello with a computed PSK binder.
    // Action: serialize the valid ticket offer and retain its final pre_shared_key extension.
    // Expected: emit a non-zero binder and preserve the exact ClientHello wire image.
    tls_session client;
    configure_tls13_psk_binder_resumption(client, context);

    // tls_handshakes owns registered handshake objects and releases them when
    // the record is destroyed. Allocate the message on the heap accordingly.
    auto client_hello = new tls_handshake_client_hello(&client);
    client_hello->add_ciphersuite(0x1301);

    auto supported_versions = new tls_extension_client_supported_versions(client_hello);
    supported_versions->add(tls1_3);
    client_hello->get_extensions().add(supported_versions);

    auto psk_modes = new tls_extension_psk_key_exchange_modes(client_hello);
    psk_modes->add(1);  // psk_dhe_ke
    client_hello->get_extensions().add(psk_modes);

    auto psk = new tls_extension_client_psk(client_hello);
    client_hello->get_extensions().add(psk);

    return_t ret = errorcode_t::success;
    tls_record_handshake record(&client);
    record << client_hello;
    binary_t& wire = context.wire;
    ret = record.write(from_client, wire);
    _test_case.test(ret, function_name, "serialize a ClientHello with a computed PSK binder");
    if (errorcode_t::success != ret) {
        return false;
    }
    bool binder_nonzero = false;
    if (wire.size() >= 32) {
        for (size_t i = wire.size() - 32; i < wire.size(); ++i) {
            binder_nonzero = binder_nonzero || (0 != wire[i]);
        }
    }
    _test_case.assert(binder_nonzero, function_name, "replace the placeholder binder before record serialization");

    return true;
}

static void test_tls13_psk_binder_rejects_malformed_offers(const char* function_name, tls13_psk_binder_test_context& context) {
    // Scenario under test: malformed TLS 1.3 pre_shared_key extension encodings.
    // Action: reorder extensions and corrupt identity, binder, or modes vectors in serialized ClientHello.
    // Expected: reject each malformed offer with the appropriate fatal alert.
    return_t ret = errorcode_t::success;
    const binary_t& wire = context.wire;
    // Move the PSK extension ahead of the other ClientHello extensions.
    // The server must reject this before attempting to validate the binder.
    size_t& extension_block = context.extension_block;
    extension_block = 5 + 4 + 2 + 32;
    extension_block += 1 + wire[extension_block];  // legacy_session_id
    uint16 cipher_suites_size = (static_cast<uint16>(wire[extension_block]) << 8) | wire[extension_block + 1];
    extension_block += 2 + cipher_suites_size;
    extension_block += 1 + wire[extension_block];  // legacy_compression_methods
    extension_block += 2;                          // extensions length
    size_t& psk_offset = context.psk_offset;
    psk_offset = extension_block;
    size_t& psk_size = context.psk_size;
    psk_size = 0;
    while (psk_offset + 4 <= wire.size()) {
        uint16 extension_type = (static_cast<uint16>(wire[psk_offset]) << 8) | wire[psk_offset + 1];
        uint16 extension_size = (static_cast<uint16>(wire[psk_offset + 2]) << 8) | wire[psk_offset + 3];
        if (static_cast<uint16>(tls_extension_type_t::pre_shared_key) == extension_type) {
            psk_size = 4 + extension_size;
            break;
        }
        psk_offset += 4 + extension_size;
    }
    _test_case.assert((psk_size > 0) && (psk_offset + psk_size == wire.size()), function_name, "locate the final pre_shared_key extension in the serialized ClientHello");
    if ((psk_size > 0) && (psk_offset + psk_size == wire.size())) {
        binary_t non_final_psk = wire;
        binary_t psk_extension(non_final_psk.begin() + psk_offset, non_final_psk.end());
        non_final_psk.erase(non_final_psk.begin() + psk_offset, non_final_psk.end());
        non_final_psk.insert(non_final_psk.begin() + extension_block, psk_extension.begin(), psk_extension.end());

        tls_session ordering_server;
        configure_tls13_psk_binder_resumption(ordering_server, context);
        tls_records ordering_records;
        ret = ordering_records.read(&ordering_server, from_client, non_final_psk);
        _test_case.assert(errorcode_t::success != ret, function_name, "reject pre_shared_key when it is not the final ClientHello extension");

        size_t illegal_parameter_count = 0;
        illegal_parameter_count = test_count_fatal_alert(ordering_server, from_client, tls_alertdesc_t::illegal_parameter);
        _test_case.assert(1 == illegal_parameter_count, function_name, "report illegal_parameter for a non-final pre_shared_key extension");
    }

    // Corrupt the PSK identity length so the vector extends beyond the
    // enclosing extension body. The payload decoder must not silently accept
    // its default-initialized fields.
    if ((psk_size > 0) && (psk_offset + psk_size == wire.size())) {
        binary_t malformed_psk = wire;
        malformed_psk[psk_offset + 6] = 0xff;
        malformed_psk[psk_offset + 7] = 0xff;
        tls_session malformed_server;
        configure_tls13_psk_binder_resumption(malformed_server, context);
        tls_records malformed_records;
        ret = malformed_records.read(&malformed_server, from_client, malformed_psk);
        _test_case.assert(errorcode_t::success != ret, function_name, "reject a PSK identity length that exceeds the extension body");
        size_t decode_error_count = 0;
        decode_error_count = test_count_fatal_alert(malformed_server, from_client, tls_alertdesc_t::decode_error);
        _test_case.assert(1 == decode_error_count, function_name, "report decode_error for a malformed PSK identity vector");
    }

    if ((psk_size > 0) && (psk_offset + psk_size == wire.size())) {
        // A PSK identity must not be empty.
        binary_t empty_identity = wire;
        empty_identity[psk_offset + 6] = 0;
        empty_identity[psk_offset + 7] = 0;
        tls_session empty_identity_server;
        configure_tls13_psk_binder_resumption(empty_identity_server, context);
        tls_records empty_identity_records;
        ret = empty_identity_records.read(&empty_identity_server, from_client, empty_identity);
        _test_case.assert(errorcode_t::success != ret, function_name, "reject an empty PSK identity");
        size_t empty_identity_decode_error_count = 0;
        empty_identity_decode_error_count = test_count_fatal_alert(empty_identity_server, from_client, tls_alertdesc_t::decode_error);
        _test_case.assert(1 == empty_identity_decode_error_count, function_name, "report decode_error for an empty PSK identity");

        // TLS 1.3 binder entries must contain the complete hash-sized value.
        uint16 identities_length = (static_cast<uint16>(wire[psk_offset + 4]) << 8) | wire[psk_offset + 5];
        size_t binders_length_offset = psk_offset + 4 + 2 + identities_length;
        if (binders_length_offset + 3 <= wire.size()) {
            binary_t short_binder = wire;
            short_binder[binders_length_offset + 2] = 31;
            tls_session short_binder_server;
            configure_tls13_psk_binder_resumption(short_binder_server, context);
            tls_records short_binder_records;
            ret = short_binder_records.read(&short_binder_server, from_client, short_binder);
            _test_case.assert(errorcode_t::success != ret, function_name, "reject a PSK binder shorter than the minimum 32 bytes");
            size_t short_binder_decode_error_count = 0;
            short_binder_decode_error_count = test_count_fatal_alert(short_binder_server, from_client, tls_alertdesc_t::decode_error);
            _test_case.assert(1 == short_binder_decode_error_count, function_name, "report decode_error for a truncated PSK binder");
        }
    }

    // Remove psk_key_exchange_modes from an otherwise valid, serialized PSK
    // ClientHello. The server, not just the local ClientHello writer, must
    // enforce RFC 8446 4.2.9 and abort with missing_extension.
    if ((psk_size > 0) && (psk_offset + psk_size == wire.size())) {
        binary_t missing_modes_wire = wire;
        size_t modes_offset = extension_block;
        size_t modes_size = 0;
        while (modes_offset + 4 <= psk_offset) {
            uint16 extension_type = (static_cast<uint16>(missing_modes_wire[modes_offset]) << 8) | missing_modes_wire[modes_offset + 1];
            uint16 extension_size = (static_cast<uint16>(missing_modes_wire[modes_offset + 2]) << 8) | missing_modes_wire[modes_offset + 3];
            if (static_cast<uint16>(tls_extension_type_t::psk_key_exchange_modes) == extension_type) {
                modes_size = 4 + extension_size;
                break;
            }
            modes_offset += 4 + extension_size;
        }
        _test_case.assert(modes_size > 0, function_name, "locate psk_key_exchange_modes in the valid ClientHello");
        if (modes_size > 0) {
            missing_modes_wire.erase(missing_modes_wire.begin() + modes_offset, missing_modes_wire.begin() + modes_offset + modes_size);
            test_write_u16(missing_modes_wire, extension_block - 2, static_cast<uint16>(test_read_u16(wire, extension_block - 2) - modes_size));
            test_write_u24(missing_modes_wire, 6, test_read_u24(wire, 6) - static_cast<uint32>(modes_size));
            test_write_u16(missing_modes_wire, 3, static_cast<uint16>(test_read_u16(wire, 3) - modes_size));

            tls_session missing_modes_server;
            configure_tls13_psk_binder_resumption(missing_modes_server, context);
            tls_records missing_modes_records;
            ret = missing_modes_records.read(&missing_modes_server, from_client, missing_modes_wire);
            _test_case.assert(errorcode_t::success != ret, function_name, "server aborts a received PSK ClientHello without psk_key_exchange_modes");
            size_t missing_extension_count = 0;
            missing_extension_count = test_count_fatal_alert(missing_modes_server, from_client, tls_alertdesc_t::missing_extension);
            _test_case.assert(1 == missing_extension_count, function_name, "report missing_extension for a received PSK offer without key-exchange modes");
        }
    }
}

static void test_tls13_psk_binder_server_validates_offers(const char* function_name, const tls13_psk_binder_test_context& context) {
    // Scenario under test: server-side TLS 1.3 PSK binder validation and identity selection.
    // Action: parse single- and multi-identity ClientHello offers with valid and malformed binders.
    // Expected: validate the selected identity, retire expired tickets, and reject malformed trailing entries.
    const binary_t& wire = context.wire;
    const uint32 ticket_age_add = context.ticket_age_add;
    const uint32 ticket_lifetime = context.ticket_lifetime;
    const binary_t& ticket = context.ticket;
    const binary_t& resumption_psk = context.resumption_psk;
    const size_t extension_block = context.extension_block;
    const size_t psk_offset = context.psk_offset;
    const size_t psk_size = context.psk_size;
    return_t ret = errorcode_t::success;
    tls_session server;
    configure_tls13_psk_binder_resumption(server, context);
    tls_records records;
    ret = records.read(&server, from_client, wire);
    _test_case.test(ret, function_name, "server parses and validates the generated ClientHello binder");
    if (errorcode_t::success == ret) {
        _test_case.assert(tls_flow_t::zero_rtt == server.get_tls_protection().get_flow(), function_name, "accept the matching PSK and enter the resumption flow");
        _test_case.assert(!server.get_tls_protection().get_secrets().get(tls_secret_t::resumption_binder_hash).empty(), function_name,
                          "retain the validated binder transcript hash");
        _test_case.assert(1 == server.get_keyvalue().get(session_client_psk_identity_count), function_name, "record the single identity offered in the ClientHello");
    }

    // Offer an unknown identity first and the cached ticket second. The
    // corresponding second binder must be selected and validated.
    if ((psk_size > 0) && (psk_offset + psk_size == wire.size())) {
        const binary_t unknown_ticket = {0x91, 0x92, 0x93};
        binary_t identities;
        test_append_u16(identities, t_narrow_cast(unknown_ticket.size()));
        identities.insert(identities.end(), unknown_ticket.begin(), unknown_ticket.end());
        test_append_u32(identities, 0);
        test_append_u16(identities, t_narrow_cast(ticket.size()));
        identities.insert(identities.end(), ticket.begin(), ticket.end());
        test_append_u32(identities, ticket_age_add + 25);

        binary_t psk_body;
        test_append_u16(psk_body, t_narrow_cast(identities.size()));
        psk_body.insert(psk_body.end(), identities.begin(), identities.end());
        test_append_u16(psk_body, 66);  // two SHA-256 binder entries
        psk_body.push_back(32);
        psk_body.insert(psk_body.end(), 32, 0);
        psk_body.push_back(32);
        psk_body.insert(psk_body.end(), 32, 0);

        binary_t multi_identity_wire(wire.begin(), wire.begin() + psk_offset);
        multi_identity_wire.insert(multi_identity_wire.end(), {0x00, 0x29, static_cast<byte_t>(psk_body.size() >> 8), static_cast<byte_t>(psk_body.size())});
        multi_identity_wire.insert(multi_identity_wire.end(), psk_body.begin(), psk_body.end());
        const size_t delta = multi_identity_wire.size() - wire.size();
        test_write_u16(multi_identity_wire, psk_offset + 2, t_narrow_cast(psk_body.size()));
        test_write_u16(multi_identity_wire, extension_block - 2, static_cast<uint16>(test_read_u16(wire, extension_block - 2) + delta));
        test_write_u24(multi_identity_wire, 6, test_read_u24(wire, 6) + static_cast<uint32>(delta));
        test_write_u16(multi_identity_wire, 3, static_cast<uint16>(test_read_u16(wire, 3) + delta));

        const size_t binders_length_offset = psk_offset + 4 + 2 + identities.size();
        tls_session binder_session;
        configure_tls13_psk_binder_resumption(binder_session, context);
        auto tlsadvisor = tls_advisor::get_instance();
        const tls_cipher_suite_t* suite = tlsadvisor->hintof_cipher_suite(0x1301);
        if (nullptr == suite) {
            _test_case.assert(false, function_name, "resolve cipher suite for the second PSK binder");
        } else {
            binary_t binder_hash;
            ret = binder_session.get_tls_protection().calc_context_hash(&binder_session, suite->mac, multi_identity_wire.data() + 5, binders_length_offset - 5,
                                                                        binder_hash);
            _test_case.test(ret, function_name, "hash a ClientHello offering multiple PSK identities");
            if (errorcode_t::success == ret) {
                binary_t selected_binder;
                ret = binder_session.get_tls_protection().calc_psk_binder(&binder_session, binder_hash, selected_binder);
                _test_case.test(ret, function_name, "calculate the binder for the second offered PSK identity");
                if (errorcode_t::success == ret && selected_binder.size() == 32) {
                    const size_t second_binder_offset = binders_length_offset + 2 + 1 + 32 + 1;
                    std::copy(selected_binder.begin(), selected_binder.end(), multi_identity_wire.begin() + second_binder_offset);

                    tls_session multi_identity_server;
                    configure_tls13_psk_binder_resumption(multi_identity_server, context);
                    tls_records multi_identity_records;
                    ret = multi_identity_records.read(&multi_identity_server, from_client, multi_identity_wire);
                    _test_case.test(ret, function_name, "select and validate the binder matching the second PSK identity");
                    if (errorcode_t::success == ret) {
                        _test_case.assert(tls_flow_t::zero_rtt == multi_identity_server.get_tls_protection().get_flow(), function_name,
                                          "resume when the cached ticket is offered after an unknown identity");
                        const binary_t& server_hash = multi_identity_server.get_tls_protection().get_secrets().get(tls_secret_t::resumption_binder_hash);
                        _test_case.assert(!server_hash.empty() && binder_hash == server_hash, function_name,
                                          "retain the transcript hash used to validate the selected second binder");
                        _test_case.assert(2 == multi_identity_server.get_keyvalue().get(session_client_psk_identity_count), function_name,
                                          "record both identities from the multi-identity ClientHello");
                    }

                    // The first offered identity is present in the server cache
                    // but has expired according to the server's issuance time.
                    // The second identity remains valid and its own binder must
                    // still be selected at wire index one.
                    {
                        tls_resumption_ticket expired_ticket;
                        expired_ticket.identity = unknown_ticket;
                        // This expired SHA-384 ticket is incompatible with the
                        // 32-byte SHA-256 binder in this offer. Expiration
                        // cleanup must still happen before binder compatibility
                        // filtering skips the candidate.
                        expired_ticket.psk = binary_t(48, 0x33);
                        expired_ticket.lifetime = ticket_lifetime;
                        expired_ticket.timestamp =
                            static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count()) -
                            (static_cast<uint64>(ticket_lifetime) * 1000 + 1000);
                        expired_ticket.version = static_cast<uint16>(tls1_3);
                        expired_ticket.cipher_suite = 0x1302;

                        tls_resumption_ticket valid_ticket;
                        valid_ticket.identity = ticket;
                        valid_ticket.psk = resumption_psk;
                        valid_ticket.lifetime = ticket_lifetime;
                        valid_ticket.timestamp =
                            static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count()) - 25;
                        valid_ticket.age_add = ticket_age_add;
                        valid_ticket.version = static_cast<uint16>(tls1_3);
                        valid_ticket.cipher_suite = 0x1301;

                        // A cached ticket stores the resumption PSK, while
                        // calc_psk_binder consumes the HKDF-Extract early secret.
                        // Build the second binder with the same derivation used
                        // by the server's cached-ticket selection path.
                        binary_t cached_ticket_early_secret;
                        tls_session cached_ticket_binder_session;
                        configure_tls13_psk_binder_resumption(cached_ticket_binder_session, context);
                        ret = cached_ticket_binder_session.get_tls_protection().calc_resumption_early_secret(resumption_psk, cached_ticket_early_secret);
                        _test_case.test(ret, function_name, "derive the early secret for the cached resumption PSK");
                        if (errorcode_t::success == ret) {
                            cached_ticket_binder_session.get_tls_protection().get_secrets().assign(tls_secret_t::resumption_early, cached_ticket_early_secret);
                            binary_t cached_ticket_binder;
                            ret = cached_ticket_binder_session.get_tls_protection().calc_psk_binder(&cached_ticket_binder_session, binder_hash, cached_ticket_binder);
                            _test_case.test(ret, function_name, "calculate the binder from the cached ticket PSK");
                            if (errorcode_t::success == ret && cached_ticket_binder.size() == 32) {
                                binary_t expired_then_valid_wire = multi_identity_wire;
                                std::copy(cached_ticket_binder.begin(), cached_ticket_binder.end(), expired_then_valid_wire.begin() + second_binder_offset);

                                tls_session expired_then_valid_server;
                                configure_tls13_psk_binder_resumption(expired_then_valid_server, context);
                                expired_then_valid_server.store_resumption_ticket(expired_ticket);
                                expired_then_valid_server.store_resumption_ticket(valid_ticket);
                                tls_records expired_then_valid_records;
                                ret = expired_then_valid_records.read(&expired_then_valid_server, from_client, expired_then_valid_wire);
                                _test_case.test(ret, function_name, "skip an expired cached ticket and validate the following valid ticket binder");
                                if (errorcode_t::success == ret) {
                                    _test_case.assert(tls_flow_t::zero_rtt == expired_then_valid_server.get_tls_protection().get_flow(), function_name,
                                                      "resume using the valid ticket after the expired first identity");
                                    _test_case.assert(1 == expired_then_valid_server.get_keyvalue().get(session_server_psk_selected_identity), function_name,
                                                      "report the second wire identity after skipping the expired first ticket");
                                    auto remaining_tickets = expired_then_valid_server.get_resumption_tickets();
                                    _test_case.assert(1 == remaining_tickets.size(), function_name, "retire the expired server-side ticket record");
                                    if (1 == remaining_tickets.size()) {
                                        _test_case.assert(ticket == remaining_tickets.front().identity, function_name,
                                                          "retain the valid ticket selected from the second identity");
                                    }
                                    const binary_t& server_hash = expired_then_valid_server.get_tls_protection().get_secrets().get(tls_secret_t::resumption_binder_hash);
                                    _test_case.assert(!server_hash.empty() && binder_hash == server_hash, function_name,
                                                      "validate the binder corresponding to the second, non-expired identity");
                                }
                            } else if (errorcode_t::success == ret) {
                                _test_case.assert(false, function_name, "produce a 32-byte cached-ticket PSK binder");
                            }
                        }
                    }

                    // Duplicate identity entries can carry different client-reported ages.
                    // Ticket lifetime is determined by the server's issuance timestamp, not this age.
                    binary_t duplicate_identity_wire = multi_identity_wire;
                    std::copy(ticket.begin(), ticket.end(), duplicate_identity_wire.begin() + psk_offset + 8);
                    test_write_u32(duplicate_identity_wire, psk_offset + 11, ticket_age_add + ticket_lifetime * 1000 + 1000);
                    test_write_u32(duplicate_identity_wire, psk_offset + 20, ticket_age_add + 25);

                    tls_session duplicate_binder_session;
                    configure_tls13_psk_binder_resumption(duplicate_binder_session, context);
                    binary_t duplicate_binder_hash;
                    ret = duplicate_binder_session.get_tls_protection().calc_context_hash(&duplicate_binder_session, suite->mac, duplicate_identity_wire.data() + 5,
                                                                                          binders_length_offset - 5, duplicate_binder_hash);
                    _test_case.test(ret, function_name, "hash a ClientHello with duplicate PSK identities and different ages");
                    if (errorcode_t::success == ret) {
                        binary_t duplicate_binder;
                        ret = duplicate_binder_session.get_tls_protection().calc_psk_binder(&duplicate_binder_session, duplicate_binder_hash, duplicate_binder);
                        _test_case.test(ret, function_name, "calculate binders for duplicate PSK identities");
                        if (errorcode_t::success == ret && duplicate_binder.size() == 32) {
                            const size_t first_binder_offset = binders_length_offset + 3;
                            const size_t second_duplicate_binder_offset = first_binder_offset + 33;
                            std::copy(duplicate_binder.begin(), duplicate_binder.end(), duplicate_identity_wire.begin() + first_binder_offset);
                            std::copy(duplicate_binder.begin(), duplicate_binder.end(), duplicate_identity_wire.begin() + second_duplicate_binder_offset);

                            tls_session duplicate_identity_server;
                            configure_tls13_psk_binder_resumption(duplicate_identity_server, context);
                            tls_records duplicate_identity_records;
                            ret = duplicate_identity_records.read(&duplicate_identity_server, from_client, duplicate_identity_wire);
                            _test_case.test(ret, function_name, "process duplicate PSK identities with different client-reported ages");
                            if (errorcode_t::success == ret) {
                                _test_case.assert(tls_flow_t::zero_rtt == duplicate_identity_server.get_tls_protection().get_flow(), function_name,
                                                  "accept the PSK based on its server-side ticket record, regardless of the reported age");
                                _test_case.assert(0 == duplicate_identity_server.get_keyvalue().get(session_server_psk_selected_identity), function_name,
                                                  "select the first occurrence of a duplicated PSK identity");
                            }
                        }
                    }

                    // When duplicate identities refer to the same server-side ticket,
                    // the first offered occurrence is selected and its corresponding
                    // binder must be validated; a later valid binder cannot mask it.
                    const size_t first_binder_offset = binders_length_offset + 3;
                    const size_t second_duplicate_binder_offset = first_binder_offset + 33;
                    binary_t first_usable_duplicate_wire = duplicate_identity_wire;
                    test_write_u32(first_usable_duplicate_wire, psk_offset + 11, ticket_age_add + 25);

                    tls_session first_usable_duplicate_binder_session;
                    configure_tls13_psk_binder_resumption(first_usable_duplicate_binder_session, context);
                    binary_t first_usable_duplicate_hash;
                    ret = first_usable_duplicate_binder_session.get_tls_protection().calc_context_hash(&first_usable_duplicate_binder_session, suite->mac,
                                                                                                       first_usable_duplicate_wire.data() + 5, binders_length_offset - 5,
                                                                                                       first_usable_duplicate_hash);
                    _test_case.test(ret, function_name, "hash duplicate PSK identities with the first occurrence selected");
                    if (errorcode_t::success == ret) {
                        binary_t first_usable_duplicate_binder;
                        ret = first_usable_duplicate_binder_session.get_tls_protection().calc_psk_binder(&first_usable_duplicate_binder_session,
                                                                                                         first_usable_duplicate_hash, first_usable_duplicate_binder);
                        _test_case.test(ret, function_name, "calculate the binder for duplicate usable PSK identities");
                        if (errorcode_t::success == ret && first_usable_duplicate_binder.size() == 32) {
                            std::copy(first_usable_duplicate_binder.begin(), first_usable_duplicate_binder.end(),
                                      first_usable_duplicate_wire.begin() + first_binder_offset);
                            std::copy(first_usable_duplicate_binder.begin(), first_usable_duplicate_binder.end(),
                                      first_usable_duplicate_wire.begin() + second_duplicate_binder_offset);
                            first_usable_duplicate_wire[first_binder_offset] ^= 0x01;

                            tls_session first_usable_duplicate_server;
                            configure_tls13_psk_binder_resumption(first_usable_duplicate_server, context);
                            tls_records first_usable_duplicate_records;
                            ret = first_usable_duplicate_records.read(&first_usable_duplicate_server, from_client, first_usable_duplicate_wire);
                            _test_case.assert(errorcode_t::success != ret, function_name, "reject an invalid binder for the first eligible duplicate identity");
                        }
                    }

                    // The parser must validate the complete identities vector,
                    // even when an earlier identity is already eligible.
                    binary_t malformed_later_identity = multi_identity_wire;
                    test_write_u16(malformed_later_identity, psk_offset + 15, 0xffff);
                    tls_session malformed_later_identity_server;
                    configure_tls13_psk_binder_resumption(malformed_later_identity_server, context);
                    tls_records malformed_later_identity_records;
                    ret = malformed_later_identity_records.read(&malformed_later_identity_server, from_client, malformed_later_identity);
                    _test_case.assert(errorcode_t::success != ret, function_name, "reject an out-of-bounds later PSK identity after an eligible identity");

                    // A later identity with an incomplete obfuscated_ticket_age
                    // must not be accepted by borrowing bytes from the binder vector.
                    binary_t truncated_later_ticket_age = multi_identity_wire;
                    test_write_u16(truncated_later_ticket_age, psk_offset + 4, 17);
                    tls_session truncated_later_ticket_age_server;
                    configure_tls13_psk_binder_resumption(truncated_later_ticket_age_server, context);
                    tls_records truncated_later_ticket_age_records;
                    ret = truncated_later_ticket_age_records.read(&truncated_later_ticket_age_server, from_client, truncated_later_ticket_age);
                    _test_case.assert(errorcode_t::success != ret, function_name, "reject a later PSK identity with a truncated ticket age");

                    // Validate every binder entry, including entries after
                    // the binder corresponding to the selected identity.
                    binary_t malformed_later_binder = multi_identity_wire;
                    malformed_later_binder[second_binder_offset - 1] = 31;
                    tls_session malformed_later_binder_server;
                    configure_tls13_psk_binder_resumption(malformed_later_binder_server, context);
                    tls_records malformed_later_binder_records;
                    ret = malformed_later_binder_records.read(&malformed_later_binder_server, from_client, malformed_later_binder);
                    _test_case.assert(errorcode_t::success != ret, function_name, "reject a malformed binder after an otherwise usable PSK identity");

                    // Two identities cannot be paired with only one binder.
                    binary_t mismatched_binder_count = multi_identity_wire;
                    test_write_u16(mismatched_binder_count, binders_length_offset, 33);
                    tls_session mismatched_binder_count_server;
                    configure_tls13_psk_binder_resumption(mismatched_binder_count_server, context);
                    tls_records mismatched_binder_count_records;
                    ret = mismatched_binder_count_records.read(&mismatched_binder_count_server, from_client, mismatched_binder_count);
                    _test_case.assert(errorcode_t::success != ret, function_name, "reject a binder vector that does not match the identity vector");
                } else if (errorcode_t::success == ret) {
                    _test_case.assert(false, function_name, "produce a 32-byte SHA-256 binder for the second identity");
                }
            }
        }
    }
}

static void test_tls13_psk_binder_unknown_identity_and_tampering(const char* function_name, const tls13_psk_binder_test_context& context) {
    // Scenario under test: unknown and tampered TLS 1.3 PSK identities and binders.
    // Action: offer an unknown identity, then modify a valid ClientHello binder.
    // Expected: fall back to a full handshake for unknown identities and report decrypt_error for a modified binder.
    // An identity unknown to this server must be ignored rather than treated
    // as a fatal protocol error; continue with the full-handshake path.
    const binary_t& wire = context.wire;
    return_t ret = errorcode_t::success;
    tls_session unknown_identity_server;
    configure_tls13_psk_binder_resumption(unknown_identity_server, context);
    unknown_identity_server.get_tls_protection().get_secrets().assign(tls_secret_t::new_session_ticket, binary_t{0x99, 0x88});
    tls_records unknown_identity_records;
    ret = unknown_identity_records.read(&unknown_identity_server, from_client, wire);
    _test_case.test(ret, function_name, "ignore an unknown PSK identity and continue ClientHello processing");
    if (errorcode_t::success == ret) {
        _test_case.assert(tls_flow_t::one_rtt == unknown_identity_server.get_tls_protection().get_flow(), function_name,
                          "decline an unknown PSK and select the full-handshake path");
        _test_case.assert(0 == unknown_identity_server.get_keyvalue().get(session_tls_version), function_name,
                          "clear the previous negotiated TLS version when the PSK identity is unknown");
    }

    binary_t tampered = wire;
    tampered.back() ^= 0x01;
    tls_session rejecting_server;
    configure_tls13_psk_binder_resumption(rejecting_server, context);
    tls_records rejecting_records;
    ret = rejecting_records.read(&rejecting_server, from_client, tampered);
    _test_case.assert(errorcode_t::success != ret, function_name, "reject a ClientHello with a modified PSK binder");

    size_t decrypt_error_count = 0;
    decrypt_error_count = test_count_fatal_alert(rejecting_server, from_client, tls_alertdesc_t::decrypt_error);
    _test_case.assert(1 == decrypt_error_count, function_name, "report decrypt_error for a modified binder");
}

static void test_tls13_client_psk_binder_roundtrip() {
    // Scenario under test: TLS 1.3 client PSK binder serialization and server round-trip.
    // Action: serialize a ClientHello with a computed PSK binder and exercise malformed and multi-identity offers.
    // Expected: validate the selected binder, reject malformed vectors, and fall back safely for unknown identities.
    _test_case.begin("TLS 1.3 client PSK binder serialization and server round-trip");

    tls13_psk_binder_test_context context;
    test_tls13_psk_binder_rejects_incomplete_offers(__FUNCTION__, context);
    if (false == test_tls13_psk_binder_build_clienthello(__FUNCTION__, context)) {
        return;
    }
    test_tls13_psk_binder_rejects_malformed_offers(__FUNCTION__, context);
    test_tls13_psk_binder_server_validates_offers(__FUNCTION__, context);
    test_tls13_psk_binder_unknown_identity_and_tampering(__FUNCTION__, context);
}

void testcase_gpt_psk_binder() {
    test_tls13_psk_binder_rfc8448_vector();
    test_tls13_client_psk_binder_roundtrip();
}
