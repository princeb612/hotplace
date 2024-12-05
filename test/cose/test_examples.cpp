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

#include "sample.hpp"

void test_github_example() {
    _test_case.begin("https://github.com/cose-wg/Examples");

    const OPTION& option = _cmdline->value();

    cbor_web_key cwk;
    crypto_key key;
    cwk.add_ec_b64u(&key, "P-256", "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8", "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                    "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM", keydesc("11"));
    cwk.add_ec_b64u(&key, "P-384", "kTJyP2KSsBBhnb4kjWmMF7WHVsY55xUPgb7k64rDcjatChoZ1nvjKmYmPh5STRKc",
                    "mM0weMVU2DKsYDxDJkEP9hZiRZtB8fPfXbzINZj_fF7YQRynNWedHEyzAJOX2e8s", "ok3Nq97AXlpEusO7jIy1FZATlBP9PNReMU7DWbkLQ5dU90snHuuHVDjEPmtV0fTo",
                    keydesc("P384"));
    cwk.add_ec_b64u(&key, "P-521", "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
                    "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
                    "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt", keydesc("bilbo.baggins@hobbiton.example"));
    cwk.add_ec_b16(&key, "Ed25519", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
                   "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", keydesc("11"));
    cwk.add_ec_b16(&key, "Ed448", "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180", "",
                   "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b", keydesc("ed448"));
    cwk.add_ec_b16(&key, "P-256", "863aa7bc0326716aa59db5bf66cc660d0591d51e4891bc2e6a9baff5077d927c",
                   "ad4eed482a7985be019e9b1936c16e00190e8bcc48ee12d35ff89f0fc7a099ca", "d42044eb2cd2691e926da4871cf3529ddec6b034f824ba5e050d2c702f97c7a5",
                   keydesc("Alice Lovelace"));
    cwk.add_ec_b64u(&key, "P-256", "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0", "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
                    "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8", keydesc("meriadoc.brandybuck@buckland.example"));
    cwk.add_ec_b64u(&key, "P-256", "mPUKT_bAWGHIhg0TpjjqVsP1rXWQu_vwVOHHtNkdYoA", "8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs",
                    "AtH35vJsQ9SGjYfOsjUxYXQKrPH3FjZHmEtSKoSN8cM", keydesc("peregrin.took@tuckborough.example"));
    cwk.add_ec_b16(&key, "X25519", "7FFE91F5F932DAE92BE603F55FAC0F4C4C9328906EE550EDCB7F6F7626EBC07E", "",
                   "00a943daa2e38b2edbf0da0434eaaec6016fe25dcd5ecacbc07dc30300567655", keydesc("X25519-1"));
    cwk.add_ec_b16(&key, "X25519", "DE9EDB7D7B7DC1B4D35B61C2ECE435373F8343C85B78674DADFC7E146F882B4F", "",
                   "58AB087E624A8A4B79E17F8B83800EE66F3BB1292618B6FD1C2F8B27FF88E06B", keydesc("X25519-bob"));
    cwk.add_ec_b16(&key, "X25519", "8520F0098930A754748B7DDCB43EF75A0DBF3A0D26381AF4EBA4A98EAA9B4E6A", "",
                   "70076D0A7318A57D3C16C17251B26645DF4C2F87EBC0992AB177FBA51DB92C6A", keydesc("X25519-alice"));

    cwk.add_oct_b64u(&key, "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg", keydesc("our-secret", crypto_use_t::use_enc));
    cwk.add_oct_b64u(&key, "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYgAESIzd4iZqiEiIyQlJico", keydesc("sec-48", crypto_use_t::use_enc));
    cwk.add_oct_b64u(&key, "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYgAESIzd4iZqiEiIyQlJicoqrvM3e7_paanqKmgsbKztA", keydesc("sec-64", crypto_use_t::use_enc));
    cwk.add_rsa_b16(&key, nid_rsa,
                    "BC7E29D0DF7E20CC9DC8D509E0F68895922AF0EF452190D402C61B554334A7BF91C9A570240F994FAE1B69035BCFAD4F7E249EB26087C2665E7C958C967B1517413DC3F97A"
                    "431691A5999B257CC6CD356BAD168D929B8BAE9020750E74CF60F6FD35D6BB3FC93FC28900478694F508B33E7C00E24F90EDF37457FC3E8EFCFD2F42306301A8205AB74051"
                    "5331D5C18F0C64D4A43BE52FC440400F6BFC558A6E32884C2AF56F29E5C52780CEA7285F5C057FC0DFDA232D0ADA681B01495D9D0E32196633588E289E59035FF664F05618"
                    "9F2F10FE05827B796C326E3E748FFA7C589ED273C9C43436CDDB4A6A22523EF8BCB2221615B799966F1ABA5BC84B7A27CF",
                    "010001",
                    "0969FF04FCC1E1647C20402CF3F736D4CAE33F264C1C6EE3252CFCC77CDEF533D700570AC09A50D7646EDFB1F86A13BCABCF00BD659F27813D08843597271838BC46ED4743"
                    "FE741D9BC38E0BF36D406981C7B81FCE54861CEBFB85AD23A8B4833C1BEE18C05E4E436A869636980646EECB839E4DAF434C9C6DFBF3A55CE1DB73E4902F89384BD6F9ECD3"
                    "399FB1ED4B83F28D356C8E619F1F0DC96BBE8B75C1812CA58F360259EAEB1D17130C3C0A2715A99BE49898E871F6088A29570DC2FFA0CEFFFA27F1F055CBAABFD8894E0CC2"
                    "4F176E34EBAD32278A466F8A34A685ACC8207D9EC1FCBBD094996DC73C6305FCA31668BE57B1699D0BB456CC8871BFFBCD",
                    keydesc("meriadoc.brandybuck@rsa.example"));

    crypto_key ecdh_wrap_p256_key;
    cwk.add_ec_b64u(&ecdh_wrap_p256_key, "P-256", "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0", "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
                    "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8", keydesc("meriadoc.brandybuck@buckland.example"));
    crypto_key ecdh_wrap_p521_key;
    cwk.add_ec_b64u(&ecdh_wrap_p521_key, "P-521", "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
                    "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
                    "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt",
                    keydesc("meriadoc.brandybuck@buckland.example", "ES512"));

    crypto_key aes_ccm_key;
    cwk.add_oct_b64u(&aes_ccm_key, "hJtXIZ2uSN5kbQfbtTNWbg", keydesc("our-secret", crypto_use_t::use_enc));
    cwk.add_oct_b64u(&aes_ccm_key, "Dx4tPEtaaXiHlqW0w9Lh8B8uPUxbanmIl6a1xNPi8QA", keydesc("sec-256", crypto_use_t::use_enc));
    cwk.add_oct_b64u(&aes_ccm_key, "Dx4tPEtaaXiHlqW0w9Lh8B8uPUxbanmI", keydesc("sec-192", crypto_use_t::use_enc));
    cwk.add_oct_b64u(&aes_ccm_key, "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYgAESIzd4iZqiEiIyQlJicoqrvM3e7_paanqKmgsbKztA",
                     keydesc("sec-64", crypto_use_t::use_enc));
    cwk.add_oct_b64u(&aes_ccm_key, "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYgAESIzd4iZqiEiIyQlJico", keydesc("sec-48", crypto_use_t::use_enc));
    cwk.add_oct_b64u(&aes_ccm_key, "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg", keydesc("018c0ae5-4d9b-471b-bfd6-eef314bc7037", crypto_use_t::use_enc));

    crypto_key hmac_aes_256_key;
    cwk.add_oct_b64u(&hmac_aes_256_key, "Dx4tPEtaaXiHlqW0w9Lh8B8uPUxbanmIl6a1xNPi8QA", keydesc("our-secret", crypto_use_t::use_enc));

    crypto_key aes_gcm_02_key;
    cwk.add_oct_b64u(&aes_gcm_02_key, "Dx4tPEtaaXiHlqW0w9Lh8B8uPUxbanmI", keydesc("sec-48", crypto_use_t::use_enc));
    crypto_key aes_gcm_03_key;
    cwk.add_oct_b64u(&aes_gcm_03_key, "Dx4tPEtaaXiHlqW0w9Lh8B8uPUxbanmIl6a1xNPi8QA", keydesc("sec-64", crypto_use_t::use_enc));
    crypto_key hmac_aes_128_key;
    cwk.add_oct_b64u(&hmac_aes_128_key, "hJtXIZ2uSN5kbQfbtTNWbg", keydesc("our-secret", crypto_use_t::use_enc));

    crypto_key key_hmac_enc_02;
    cwk.add_oct_b64u(&key_hmac_enc_02, "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYgAESIzd4iZqiEiIyQlJico", keydesc("sec-48", crypto_use_t::use_enc));

    crypto_key cwtkey;
    cwk.add_ec_b16(&cwtkey, "P-256", "143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f",
                   "60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9", "6c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19",
                   keydesc());
    cwk.add_oct_b16(&cwtkey, "231f4c4d4d3051fdc2ec0a3851d5b383", keydesc("our-secret"));

    crypto_key key_cwt_a4;
    cwk.add_oct_b16(&key_cwt_a4, "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388", keydesc("our-secret"));

    crypto_key key_hmac_enc_03;
    cwk.add_oct_b64u(&key_hmac_enc_03, "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYgAESIzd4iZqiEiIyQlJicoqrvM3e7_paanqKmgsbKztA", keydesc("sec-64"));

    std::map<std::string, crypto_key*> keymapper;

    keymapper["rfc8152_privkeys"] = &rfc8152_privkeys;
    keymapper["rfc8152_pubkeys"] = &rfc8152_pubkeys;
    keymapper["rfc8152_privkeys_c4"] = &rfc8152_privkeys_c4;
    keymapper["key"] = &key;
    keymapper["ecdh_wrap_p256_key"] = &ecdh_wrap_p256_key;
    keymapper["ecdh_wrap_p521_key"] = &ecdh_wrap_p521_key;
    keymapper["aes_ccm_key"] = &aes_ccm_key;
    keymapper["hmac_aes_256_key"] = &hmac_aes_256_key;
    keymapper["aes_gcm_02_key"] = &aes_gcm_02_key;
    keymapper["aes_gcm_03_key"] = &aes_gcm_03_key;
    keymapper["hmac_aes_128_key"] = &hmac_aes_128_key;
    keymapper["key_hmac_enc_02"] = &key_hmac_enc_02;
    keymapper["cwtkey"] = &cwtkey;
    keymapper["key_cwt_a4"] = &key_cwt_a4;
    keymapper["key_hmac_enc_03"] = &key_hmac_enc_03;

    int i = 0;
    cbor_encode e;

    std::map<std::string, int> dictionary;
    std::map<std::string, int>::iterator iter;
    uint16 table[] = {
        cbor_tag_t::cose_tag_encrypt0,  // 16
        cbor_tag_t::cose_tag_mac0,      // 17
        cbor_tag_t::cose_tag_sign1,     // 18
        cbor_tag_t::cose_tag_encrypt,   // 96
        cbor_tag_t::cose_tag_mac,       // 97
        cbor_tag_t::cose_tag_sign,      // 98
    };
    for (i = 0; i < RTL_NUMBER_OF(table); i++) {
        binary_t bin;
        e.encode(bin, cbor_major_t::cbor_major_tag, table[i]);
        std::string keyword = uppername(base16_encode(bin));
        dictionary.insert(std::make_pair(keyword, table[i]));
        _logger->writeln("%s => %i", keyword.c_str(), table[i]);
    }

    _test_case.reset_time();

    basic_stream bs;
    bool result = false;
    cbor_object_signing_encryption cose;
    for (i = 0; i < sizeof_test_vector_github_cose_wg; i++) {
        const test_vector_github_cose_wg_t* vector = test_vector_github_cose_wg + i;
        if (vector->skip) {
            continue;
        }
        if (vector->debug) {
            int break_point_here = 1;
        }

        _logger->colorln(vector->file);
        binary_t cbor = base16_decode(vector->cbor);
        crypto_key* mapped_key = keymapper[vector->keysetname];

        mapped_key->for_each(dump_crypto_key, nullptr);

        binary_t bin_cbor;
        basic_stream bs;
        basic_stream diagnostic;
        cbor_reader reader;
        cbor_reader_context_t* reader_handle = nullptr;
        reader.open(&reader_handle);
        reader.parse(reader_handle, cbor);
        reader.publish(reader_handle, &diagnostic);
        reader.publish(reader_handle, &bin_cbor);
        reader.close(reader_handle);
        if (option.verbose) {
            dump_memory(bin_cbor, &bs, 16, 2);
            _logger->writeln("cbor\n%s", bs.c_str());
            _logger->writeln("diagnostic\n  %s", diagnostic.c_str());

            cbor_publisher publisher;
            cose_composer composer;
            basic_stream bs_diagnostic_composed;
            binary_t bin_composed;
            cbor_array* cbor_newone = nullptr;

            composer.parse(cbor);
            composer.compose(&cbor_newone, bin_composed, vector->untagged ? false : true);

            publisher.publish(cbor_newone, &bs_diagnostic_composed);
            dump_test_data("compose", bs_diagnostic_composed);
            _test_case.assert(bin_composed == bin_cbor, __FUNCTION__, "compose.parse %s", vector->file);
        }

        basic_stream properties;
        basic_stream reason;
        basic_stream debug_stream;
        return_t ret = errorcode_t::success;

        cose_context_t* handle = nullptr;
        cose.open(&handle);

#define dumps(b, f)                                       \
    if (f) {                                              \
        dump_memory(base16_decode(f), &bs, 16, 2);        \
        _logger->colorln(">%s %s\n%s", b, f, bs.c_str()); \
    }

        if (option.verbose) {
            cose.set(handle, cose_flag_t::cose_flag_allow_debug);

            dumps("AAD", vector->enc.aad_hex);
            dumps("CEK", vector->enc.cek_hex);
            dumps("external", vector->shared.external);
            dumps("unsent iv", vector->shared.iv_hex);
            dumps("unsent partyu id", vector->shared.apu_id);
            dumps("unsent partyu nonce", vector->shared.apu_nonce);
            dumps("unsent partyu other", vector->shared.apu_other);
            dumps("unsent partyv id", vector->shared.apv_id);
            dumps("unsent partyv nonce", vector->shared.apv_nonce);
            dumps("unsent partyv other", vector->shared.apv_other);
            dumps("unsent pub other", vector->shared.pub_other);
            dumps("unsent private", vector->shared.priv);
        }

        if (vector->shared.external) {
            cose.set(handle, cose_param_t::cose_external, base16_decode(vector->shared.external));
            properties << "external ";
        }
        if (vector->shared.iv_hex) {
            cose.set(handle, cose_param_t::cose_unsent_iv, base16_decode(vector->shared.iv_hex));
            properties << "iv ";
        }
        if (vector->shared.apu_id) {
            cose.set(handle, cose_param_t::cose_unsent_apu_id, base16_decode(vector->shared.apu_id));
            properties << "apu_id ";
        }
        if (vector->shared.apu_nonce) {
            cose.set(handle, cose_param_t::cose_unsent_apu_nonce, base16_decode(vector->shared.apu_nonce));
            properties << "apu_nonce ";
        }
        if (vector->shared.apu_other) {
            cose.set(handle, cose_param_t::cose_unsent_apu_other, base16_decode(vector->shared.apu_other));
            properties << "external apu_other";
        }
        if (vector->shared.apv_id) {
            cose.set(handle, cose_param_t::cose_unsent_apv_id, base16_decode(vector->shared.apv_id));
            properties << "apv_id ";
        }
        if (vector->shared.apv_nonce) {
            cose.set(handle, cose_param_t::cose_unsent_apv_nonce, base16_decode(vector->shared.apv_nonce));
            properties << "apv_nonce ";
        }
        if (vector->shared.apv_other) {
            cose.set(handle, cose_param_t::cose_unsent_apv_other, base16_decode(vector->shared.apv_other));
            properties << "apv_other ";
        }
        if (vector->shared.pub_other) {
            cose.set(handle, cose_param_t::cose_unsent_pub_other, base16_decode(vector->shared.pub_other));
            properties << "pub_other ";
        }
        if (vector->shared.priv) {
            cose.set(handle, cose_param_t::cose_unsent_priv_other, base16_decode(vector->shared.priv));
            properties << "priv ";
        }

        binary_t output;
        ret = cose.process(handle, mapped_key, cbor, output);

        if (option.verbose) {
            uint32 flags = 0;
            uint32 debug_flags = 0;
            cose.get(handle, flags, debug_flags);
            if (debug_flags & cose_debug_notfound_key) {
                reason << "!key ";
            }
            if (debug_flags & cose_debug_partial_iv) {
                reason << "partial_iv ";
            }
            if (debug_flags & cose_debug_counter_sig) {
                reason << "counter_sig ";
            }
            debug_stream = handle->debug_stream;
            if (output.size()) {
                dump_memory(output, &bs, 16, 4);
                _logger->writeln("decrypted\n%s\n%s", bs.c_str(), base16_encode(output).c_str());
            }
        }

        cose.close(handle);

        _test_case.test(ret, __FUNCTION__, "%s %s %s%s%s%s", vector->file, properties.c_str(), reason.size() ? "[ debug : " : "", reason.c_str(),
                        reason.size() ? "] " : " ", debug_stream.c_str());
    }
}
