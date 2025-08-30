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

crypto_key rfc8152_privkeys;
crypto_key rfc8152_pubkeys;
crypto_key rfc8152_privkeys_c4;

return_t do_test_cose_example(cose_context_t* cose_handle, crypto_key* cose_keys, cbor_object* root, const char* expect_file, const char* text) {
    return_t ret = errorcode_t::success;
    return_t test = errorcode_t::success;
    const OPTION& option = _cmdline->value();

    __try2 {
        if (nullptr == cose_handle || nullptr == cose_keys || nullptr == root || nullptr == expect_file) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_publisher publisher;
        // cbor_object* to cbor
        binary_t bin;
        publisher.publish(root, &bin);

        if (option.verbose) {
            // cbor_object* to diagnostic
            basic_stream diagnostic;
            // publisher.publish(root, &diagnostic);

            // load cbor from file
            binary_t expect;
            {
                test_case_notimecheck notimecheck(_test_case);

                file_stream fs;
                ret = fs.open(expect_file);
                if (errorcode_t::success != ret) {
                    __leave2;
                }
                fs.begin_mmap();

                byte_t* file_contents = fs.data();
                size_t file_size = fs.size();
                expect.insert(expect.end(), file_contents, file_contents + file_size);

                cbor_reader reader;
                cbor_reader_context_t* handle = nullptr;
                cbor_object* newone = nullptr;

                reader.open(&handle);
                reader.parse(handle, expect);
                reader.publish(handle, &diagnostic);
                reader.close(handle);

                dump_test_data("test vector #1", expect);
                dump_test_data("diagnostic #1", diagnostic);
            }

            _test_case.assert((bin == expect), __FUNCTION__, "check1.cborcheck %s", text ? text : "");

            // parse
            basic_stream bs_diagnostic_lv1;
            binary_t bin_cbor_lv1;

            cbor_reader reader;
            cbor_reader_context_t* handle = nullptr;
            cbor_object* newone = nullptr;

            reader.open(&handle);
            reader.parse(handle, bin);
            // cbor_reader_context_t* to diagnostic
            reader.publish(handle, &bs_diagnostic_lv1);
            // cbor_reader_context_t* to cbor
            reader.publish(handle, &bin_cbor_lv1);
            // cbor_reader_context_t* to cbor_object*
            reader.publish(handle, &newone);
            reader.close(handle);

            if (newone) {
                {
                    test_case_notimecheck notimecheck(_test_case);

                    dump_test_data("diagnostic #2", bs_diagnostic_lv1);
                    dump_test_data("cbor #2", bin_cbor_lv1);
                }

                _test_case.assert((bin_cbor_lv1 == expect), __FUNCTION__, "check2.cborparse %s", text ? text : "");

                // parsed cbor_object* to diagnostic
                basic_stream bs_diagnostic_lv2;
                publisher.publish(newone, &bs_diagnostic_lv2);

                // parsed cbor_object* to cbor
                binary_t bin_cbor_lv2;
                publisher.publish(newone, &bin_cbor_lv2);

                {
                    test_case_notimecheck notimecheck(_test_case);

                    dump_test_data("diagnostic #3", bs_diagnostic_lv2);
                    dump_test_data("cbor #3", bin_cbor_lv2);
                }

                _test_case.assert((bin_cbor_lv2 == expect), __FUNCTION__, "check3.cborparse %s", text ? text : "");

                {
                    test_case_notimecheck notimecheck(_test_case);
                    cose_composer composer;
                    binary_t bin_untagged;
                    basic_stream bs_diagnostic_composed;
                    cbor_array* cbor_newone = nullptr;

                    cbor_tag_t tag = newone->tag_value();  // backup
                    if (cbor_tag_t::cbor_tag_unknown != tag) {
                        newone->tag(cbor_tag_t::cbor_tag_unknown);

                        publisher.publish(newone, &bin_untagged);
                        composer.parse(bin_untagged);
                        composer.compose(&cbor_newone);

                        publisher.publish(cbor_newone, &bs_diagnostic_composed);
                        dump_test_data("compose", bs_diagnostic_composed);

                        _test_case.assert(false == bin_untagged.empty(), __FUNCTION__, "check.compose %s", text ? text : "");

                        cbor_newone->release();
                    }
                }
                newone->release();  // release parsed object
            }
        }

        cbor_object_signing_encryption cose;
        binary_t signature;
        binary_t decrypted;
        bool result = false;

        if (root->tagged()) {
            switch (root->tag_value()) {
                case cbor_tag_t::cose_tag_sign:
                case cbor_tag_t::cose_tag_sign1:
                    ret = cose.verify(cose_handle, cose_keys, bin, result);
                    _test_case.test(ret, __FUNCTION__, "check4.verify %s", text ? text : "");
                    break;
                case cbor_tag_t::cose_tag_encrypt:
                case cbor_tag_t::cose_tag_encrypt0:
                    ret = cose.decrypt(cose_handle, cose_keys, bin, decrypted, result);
                    if (errorcode_t::success == ret) {
                        if (option.verbose) {
                            _logger->dump(decrypted, 16, 4);
                        }
                    }
                    _test_case.test(ret, __FUNCTION__, "check4.decrypt %s", text ? text : "");
                    break;
                case cbor_tag_t::cose_tag_mac:
                case cbor_tag_t::cose_tag_mac0:
                    ret = cose.verify(cose_handle, cose_keys, bin, result);
                    _test_case.test(ret, __FUNCTION__, "check4.verify %s", text ? text : "");
                    break;
                default:
                    break;
            }
        }
    }
    __finally2 {}
    return ret;
}

void do_test_cbor_file(const char* expect_file, const char* text) {
    _test_case.begin("parse and generate diagnostic from RFC examples");
    const OPTION& option = _cmdline->value();

    console_color concolor;

    basic_stream bs;
    bs << concolor.turnon().set_style(console_style_t::bold).set_fgcolor(console_color_t::cyan) << expect_file << concolor.turnoff();
    _logger->writeln(bs);

    return_t ret = errorcode_t::success;

    __try2 {
        binary_t expect;
        file_stream fs;
        ret = fs.open(expect_file);
        if (errorcode_t::success == ret) {
            fs.begin_mmap();

            byte_t* file_contents = fs.data();
            size_t file_size = fs.size();
            expect.insert(expect.end(), file_contents, file_contents + file_size);
        } else {
            __leave2;
        }

        basic_stream bs_diagnostic;
        binary_t bin_cbor;

        cbor_reader reader;
        cbor_reader_context_t* handle = nullptr;
        cbor_object* root = nullptr;

        reader.open(&handle);
        reader.parse(handle, expect);
        reader.publish(handle, &bs_diagnostic);
        reader.publish(handle, &bin_cbor);
        reader.publish(handle, &root);
        reader.close(handle);

        if (option.verbose) {
            dump_test_data("diagnostic", bs_diagnostic);
            dump_test_data("cbor", bin_cbor);
        }

        root->release();

        _test_case.assert((bin_cbor == expect), __FUNCTION__, text ? text : "");
    }
    __finally2 {}
}

void test_rfc8152_b() {
    _test_case.begin("RFC 8152 B");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_aes128gcm);
    composer.get_unprotected().add(cose_key_t::cose_iv, base16_decode("02d1f7e6f26c43d4868d87ce"));
    composer.get_payload().set(base16_decode("64f84d913ba60a76070a9a48f26e97e863e2852948658f0811139868826e89218a75715b"));

    cose_recipient& recipient = composer.get_recipients().add(new cose_recipient);
    recipient.get_unprotected().add(cose_key_t::cose_alg, cose_alg_t::cose_aes128kw);
    recipient.get_payload().set(base16_decode("dbd43c4e9d719c27c6275c67d628d493f090593db8218f11"));

    cose_recipient& layered_recipient = recipient.add(new cose_recipient);
    layered_recipient.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_ecdhes_hkdf_256);
    layered_recipient.get_unprotected()
        .add(cose_key_t::cose_ephemeral_key, cose_ec_curve_t::cose_ec_p256, base16_decode("b2add44368ea6d641f9ca9af308b4079aeb519f11e9b8a55a600b21233e86e68"),
             false)
        .add(cose_key_t::cose_kid, "meriadoc.brandybuck@buckland.example");

    composer.compose(&root);

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    do_test_cose_example(cose_handle, &rfc8152_privkeys, root, "rfc8152_b.cbor", "RFC 8152 B.  Two Layers of Recipient Information");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_1_1() {
    _test_case.begin("RFC 8152 C.1");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_payload().set("This is the content.");

    cose_recipient& signature = composer.get_recipients().add(new cose_recipient);
    signature.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_es256);
    signature.get_unprotected().add(cose_key_t::cose_kid, "11");
    signature.get_payload().set_b16(
        "e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a");
    composer.compose(&root);

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    do_test_cose_example(cose_handle, &rfc8152_pubkeys, root, "rfc8152_c_1_1.cbor", "RFC 8152 C.1.1.  Single Signature");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_1_2() {
    _test_case.begin("RFC 8152 C.1");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_payload().set("This is the content.");

    cose_recipient& signature = composer.get_recipients().add(new cose_recipient);
    signature.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_es256);
    signature.get_unprotected().add(cose_key_t::cose_kid, "11");
    signature.get_payload().set_b16(
        "e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a");

    cose_recipient& signature2 = composer.get_recipients().add(new cose_recipient);
    signature2.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_es512);
    signature2.get_unprotected().add(cose_key_t::cose_kid, "bilbo.baggins@hobbiton.example");
    signature2.get_payload().set_b16(
        "00a2d28a7c2bdb1587877420f65adf7d0b9a06635dd1de64bb62974c863f0b160dd2163734034e6ac003b01e8705524c5c4ca479a952f0247ee8cb0b4fb7397ba08d009e0c8bf4"
        "82270cc5771aa143966e5a469a09f613488030c5b07ec6d722e3835adb5b2d8c44e95ffb13877dd2582866883535de3bb03d01753f83ab87bb4f7a0297");

    composer.compose(&root);

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    do_test_cose_example(cose_handle, &rfc8152_pubkeys, root, "rfc8152_c_1_2.cbor", "RFC 8152 C.1.2.  Multiple Signers");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_1_3() {
    _test_case.begin("RFC 8152 C.1");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_unprotected().add(
        cose_alg_t::cose_es256, "11",
        base16_decode("5ac05e289d5d0e1b0a7f048a5d2b643813ded50bc9e49220f4f7278f85f19d4a77d655c9d3b51e805a74b099e1e085aacd97fc29d72f887e8802bb6650cceb2c"));
    composer.get_payload().set("This is the content.");

    cose_recipient& signature = composer.get_recipients().add(new cose_recipient);
    signature.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_es256);
    signature.get_unprotected().add(cose_key_t::cose_kid, "11");
    signature.get_payload().set_b16(
        "e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a");

    composer.compose(&root);

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    do_test_cose_example(cose_handle, &rfc8152_pubkeys, root, "rfc8152_c_1_3.cbor", "RFC 8152 C.1.3.  Counter Signature");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_1_4() {
    _test_case.begin("RFC 8152 C.1");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_protected().set(base16_decode("a2687265736572766564f40281687265736572766564"));
    composer.get_payload().set("This is the content.");

    cose_recipient& signature = composer.get_recipients().add(new cose_recipient);
    signature.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_es256);
    signature.get_unprotected().add(cose_key_t::cose_kid, "11");
    signature.get_payload().set_b16(
        "3fc54702aa56e1b2cb20284294c9106a63f91bac658d69351210a031d8fc7c5ff3e4be39445b1a3e83e1510d1aca2f2e8a7c081c7645042b18aba9d1fad1bd9c");

    composer.compose(&root);

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    do_test_cose_example(cose_handle, &rfc8152_pubkeys, root, "rfc8152_c_1_4.cbor", "RFC 8152 C.1.4.  Signature with Criticality");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_2_1() {
    _test_case.begin("RFC 8152 C.2");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_es256);
    composer.get_unprotected().add(cose_key_t::cose_kid, "11");
    composer.get_payload().set("This is the content.");
    composer.get_singleitem().set_b16(
        "8eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4d25a91aef0b0117e2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b0916e5a4c345cacb36");

    composer.compose(&root);

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    do_test_cose_example(cose_handle, &rfc8152_pubkeys, root, "rfc8152_c_2_1.cbor", "RFC 8152 C.2.1.  Single ECDSA Signature");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_3_1() {
    _test_case.begin("RFC 8152 C.3");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_aes128gcm);
    composer.get_unprotected().add(cose_key_t::cose_iv, base16_decode("c9cf4df2fe6c632bf7886413"));
    composer.get_payload().set_b16("7adbe2709ca818fb415f1e5df66f4e1a51053ba6d65a1a0c52a357da7a644b8070a151b0");

    cose_recipient& recipient = composer.get_recipients().add(new cose_recipient);
    recipient.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_ecdhes_hkdf_256);
    recipient.get_unprotected()
        .add(cose_key_t::cose_ephemeral_key, cose_ec_curve_t::cose_ec_p256, base16_decode("98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280"),
             true)
        .add(cose_key_t::cose_kid, "meriadoc.brandybuck@buckland.example");

    composer.compose(&root);

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    do_test_cose_example(cose_handle, &rfc8152_privkeys, root, "rfc8152_c_3_1.cbor", "RFC 8152 C.3.1.  Direct ECDH");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_3_2() {
    _test_case.begin("RFC 8152 C.3");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_aesccm_16_64_128);
    composer.get_unprotected().add(cose_key_t::cose_iv, base16_decode("89f52f65a1c580933b5261a76c"));
    composer.get_payload().set_b16("753548a19b1307084ca7b2056924ed95f2e3b17006dfe931b687b847");

    cose_recipient& recipient = composer.get_recipients().add(new cose_recipient);
    recipient.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_hkdf_sha256);
    recipient.get_unprotected().add(cose_key_t::cose_salt, "aabbccddeeffgghh").add(cose_key_t::cose_kid, "our-secret");

    composer.compose(&root);

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);

    cose.set(cose_handle, cose_param_t::cose_unsent_apu_id, str2bin("lighting-client"));
    cose.set(cose_handle, cose_param_t::cose_unsent_apv_id, str2bin("lighting-server"));
    cose.set(cose_handle, cose_param_t::cose_unsent_pub_other, str2bin("Encryption Example 02"));

    do_test_cose_example(cose_handle, &rfc8152_privkeys, root, "rfc8152_c_3_2.cbor", "RFC 8152 C.3.2.  Direct Plus Key Derivation");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_3_3() {
    _test_case.begin("RFC 8152 C.3");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_aes128gcm);
    composer.get_unprotected()
        .add(cose_key_t::cose_iv, base16_decode("c9cf4df2fe6c632bf7886413"))
        .add(cose_alg_t::cose_es512, "bilbo.baggins@hobbiton.example",
             base16_decode("00929663c8789bb28177ae28467e66377da12302d7f9594d2999afa5dfa531294f8896f2b6cdf1740014f4c7f1a358e3a6cf57f4ed6fb02fcf8f7aa989f5dfd07f0"
                           "700a3a7d8f3c604"
                           "ba70fa9411bd10c2591b483e1d2c31de003183e434d8fba18f17a4c7e3dfa003ac1cf3d30d44d2533c4989d3ac38c38b71481cc3430c9d65e7ddff"));
    composer.get_payload().set_b16("7adbe2709ca818fb415f1e5df66f4e1a51053ba6d65a1a0c52a357da7a644b8070a151b0");

    cose_recipient& recipient = composer.get_recipients().add(new cose_recipient);
    recipient.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_ecdhes_hkdf_256);
    recipient.get_unprotected()
        .add(cose_key_t::cose_ephemeral_key, cose_ec_curve_t::cose_ec_p256, base16_decode("98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280"),
             true)
        .add(cose_key_t::cose_kid, "meriadoc.brandybuck@buckland.example");

    composer.compose(&root);

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    do_test_cose_example(cose_handle, &rfc8152_privkeys, root, "rfc8152_c_3_3.cbor", "RFC 8152 C.3.3.  Counter Signature on Encrypted Content");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_3_4() {
    _test_case.begin("RFC 8152 C.3");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_aes128gcm);
    composer.get_unprotected().add(cose_key_t::cose_iv, base16_decode("02d1f7e6f26c43d4868d87ce"));
    composer.get_payload().set_b16("64f84d913ba60a76070a9a48f26e97e863e28529d8f5335e5f0165eee976b4a5f6c6f09d");

    cose_recipient& recipient = composer.get_recipients().add(new cose_recipient);
    recipient.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_ecdhss_a128kw);
    recipient.get_unprotected()
        .add(cose_key_t::cose_static_key_id, "peregrin.took@tuckborough.example")
        .add(cose_key_t::cose_kid, "meriadoc.brandybuck@buckland.example")
        .add(cose_key_t::cose_partyu_nonce, base16_decode("0101"));
    recipient.get_payload().set_b16("41e0d76f579dbd0d936a662d54d8582037de2e366fde1c62");

    composer.compose(&root);

    // Externally Supplied AAD: h'0011bbcc22dd44ee55ff660077'
    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    cose.set(cose_handle, cose_param_t::cose_external, base16_decode("0011bbcc22dd44ee55ff660077"));
    do_test_cose_example(cose_handle, &rfc8152_privkeys, root, "rfc8152_c_3_4.cbor", "RFC 8152 C.3.4.  Encrypted Content with External Data");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_4_1() {
    _test_case.begin("RFC 8152 C.4");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_aesccm_16_64_128);
    composer.get_unprotected().add(cose_key_t::cose_iv, base16_decode("89f52f65a1c580933b5261a78c"));
    composer.get_payload().set_b16("5974e1b99a3a4cc09a659aa2e9e7fff161d38ce71cb45ce460ffb569");

    composer.compose(&root);

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    do_test_cose_example(cose_handle, &rfc8152_privkeys_c4, root, "rfc8152_c_4_1.cbor", "RFC 8152 C.4.1.  Simple Encrypted Message");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_4_2() {
    _test_case.begin("RFC 8152 C.4");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_aesccm_16_64_128);
    composer.get_unprotected().add(cose_key_t::cose_partial_iv, base16_decode("61a7"));
    composer.get_payload().set_b16("252a8911d465c125b6764739700f0141ed09192de139e053bd09abca");

    composer.compose(&root);

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    cose.set(cose_handle, cose_param_t::cose_unsent_iv, base16_decode("89F52F65A1C5809300000061A7"));
    do_test_cose_example(cose_handle, &rfc8152_privkeys_c4, root, "rfc8152_c_4_2.cbor", "RFC 8152 C.4.2.  Encrypted Message with a Partial IV");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_5_1() {
    _test_case.begin("RFC 8152 C.5");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_aesmac_256_64);
    composer.get_payload().set("This is the content.");
    composer.get_tag().set_b16("9e1226ba1f81b848");

    cose_recipient& recipient = composer.get_recipients().add(new cose_recipient);
    recipient.get_unprotected().add(cose_key_t::cose_alg, cose_alg_t::cose_direct).add(cose_key_t::cose_kid, "our-secret");

    composer.compose(&root);

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    do_test_cose_example(cose_handle, &rfc8152_privkeys, root, "rfc8152_c_5_1.cbor", "RFC 8152 C.5.1.  Shared Secret Direct MAC");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_5_2() {
    _test_case.begin("RFC 8152 C.5");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_hs256);
    composer.get_payload().set("This is the content.");
    composer.get_tag().set_b16("81a03448acd3d305376eaa11fb3fe416a955be2cbe7ec96f012c994bc3f16a41");

    cose_recipient& recipient = composer.get_recipients().add(new cose_recipient);
    recipient.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_ecdhss_hkdf_256);
    recipient.get_unprotected()
        .add(cose_key_t::cose_static_key_id, "peregrin.took@tuckborough.example")
        .add(cose_key_t::cose_kid, "meriadoc.brandybuck@buckland.example")
        .add(cose_key_t::cose_partyu_nonce,
             base16_decode("4d8553e7e74f3c6a3a9dd3ef286a8195cbf8a23d19558ccfec7d34b824f42d92bd06bd2c7f0271f0214e141fb779ae2856abf585a58368b017e7f2a9e5ce4db5"));

    composer.compose(&root);

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    do_test_cose_example(cose_handle, &rfc8152_privkeys, root, "rfc8152_c_5_2.cbor", "RFC 8152 C.5.2.  ECDH Direct MAC");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_5_3() {
    _test_case.begin("RFC 8152 C.5");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_aesmac_128_64);
    composer.get_payload().set("This is the content.");
    composer.get_tag().set_b16("36f5afaf0bab5d43");

    cose_recipient& recipient = composer.get_recipients().add(new cose_recipient);
    recipient.get_unprotected().add(cose_key_t::cose_alg, cose_alg_t::cose_aes256kw).add(cose_key_t::cose_kid, "018c0ae5-4d9b-471b-bfd6-eef314bc7037");
    recipient.get_payload().set_b16("711ab0dc2fc4585dce27effa6781c8093eba906f227b6eb0");

    composer.compose(&root);

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    do_test_cose_example(cose_handle, &rfc8152_privkeys, root, "rfc8152_c_5_3.cbor", "RFC 8152 C.5.3.  Wrapped MAC");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_5_4() {
    _test_case.begin("RFC 8152 C.5");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_hs256);
    composer.get_payload().set("This is the content.");
    composer.get_tag().set_b16("bf48235e809b5c42e995f2b7d5fa13620e7ed834e337f6aa43df161e49e9323e");

    cose_recipient& recipient = composer.get_recipients().add(new cose_recipient);
    recipient.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_ecdhes_a128kw);
    recipient.get_unprotected()
        .add(cose_key_t::cose_ephemeral_key, cose_ec_curve_t::cose_ec_p521,
             base16_decode(
                 "0043b12669acac3fd27898ffba0bcd2e6c366d53bc4db71f909a759304acfb5e18cdc7ba0b13ff8c7636271a6924b1ac63c02688075b55ef2d613574e7dc242f79c3"),
             true)
        .add(cose_key_t::cose_kid, "bilbo.baggins@hobbiton.example");
    recipient.get_payload().set_b16("339bc4f79984cdc6b3e6ce5f315a4c7d2b0ac466fcea69e8c07dfbca5bb1f661bc5f8e0df9e3eff5");

    cose_recipient& recipient2 = composer.get_recipients().add(new cose_recipient);
    recipient2.get_unprotected().add(cose_key_t::cose_alg, cose_alg_t::cose_aes256kw).add(cose_key_t::cose_kid, "018c0ae5-4d9b-471b-bfd6-eef314bc7037");
    recipient2.get_payload().set_b16("0b2c7cfce04e98276342d6476a7723c090dfdd15f9a518e7736549e998370695e6d6a83b4ae507bb");

    composer.compose(&root);

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    do_test_cose_example(cose_handle, &rfc8152_privkeys, root, "rfc8152_c_5_4.cbor", "RFC 8152 C.5.4.  Multi-Recipient MACed Message");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_6_1() {
    _test_case.begin("RFC 8152 C.6");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_aesmac_256_64);
    composer.get_payload().set("This is the content.");
    composer.get_tag().set_b16("726043745027214f");

    composer.compose(&root);

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    do_test_cose_example(cose_handle, &rfc8152_privkeys, root, "rfc8152_c_6_1.cbor", "RFC 8152 C.6.1.  Shared Secret Direct MAC");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_7_1() {
    _test_case.begin("RFC 8152 C.7");

    cbor_array* root = new cbor_array();
    {
        cbor_map* key = new cbor_map();

        *key << new cbor_pair(cose_key_lable_t::cose_ec_crv, new cbor_data(cose_ec_curve_t::cose_ec_p256))
             << new cbor_pair(cose_key_lable_t::cose_ec_x, new cbor_data(base16_decode("65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d")))
             << new cbor_pair(cose_key_lable_t::cose_ec_y, new cbor_data(base16_decode("1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c")))
             << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(cose_kty_t::cose_kty_ec2))
             << new cbor_pair(cose_key_lable_t::cose_lable_kid, new cbor_data(str2bin("meriadoc.brandybuck@buckland.example")));

        *root << key;
    }
    {
        cbor_map* key = new cbor_map();

        *key << new cbor_pair(cose_key_lable_t::cose_ec_crv, new cbor_data(cose_ec_curve_t::cose_ec_p256))
             << new cbor_pair(cose_key_lable_t::cose_ec_x, new cbor_data(base16_decode("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff")))
             << new cbor_pair(cose_key_lable_t::cose_ec_y, new cbor_data(base16_decode("20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e")))
             << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(cose_kty_t::cose_kty_ec2))
             << new cbor_pair(cose_key_lable_t::cose_lable_kid, new cbor_data(str2bin("11")));

        *root << key;
    }
    {
        cbor_map* key = new cbor_map();

        *key
            << new cbor_pair(cose_key_lable_t::cose_ec_crv, new cbor_data(cose_ec_curve_t::cose_ec_p521))
            << new cbor_pair(
                   cose_key_lable_t::cose_ec_x,
                   new cbor_data(base16_decode(
                       "0072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad")))
            << new cbor_pair(
                   cose_key_lable_t::cose_ec_y,
                   new cbor_data(base16_decode(
                       "01dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1d9475")))
            << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(cose_kty_t::cose_kty_ec2))
            << new cbor_pair(cose_key_lable_t::cose_lable_kid, new cbor_data(str2bin("bilbo.baggins@hobbiton.example")));

        *root << key;
    }
    {
        cbor_map* key = new cbor_map();

        *key << new cbor_pair(cose_key_lable_t::cose_ec_crv, new cbor_data(cose_ec_curve_t::cose_ec_p256))
             << new cbor_pair(cose_key_lable_t::cose_ec_x, new cbor_data(base16_decode("98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280")))
             << new cbor_pair(cose_key_lable_t::cose_ec_y, new cbor_data(base16_decode("f01400b089867804b8e9fc96c3932161f1934f4223069170d924b7e03bf822bb")))
             << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(cose_kty_t::cose_kty_ec2))
             << new cbor_pair(cose_key_lable_t::cose_lable_kid, new cbor_data(str2bin("peregrin.took@tuckborough.example")));

        *root << key;
    }

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    do_test_cose_example(cose_handle, &rfc8152_pubkeys, root, "rfc8152_c_7_1.cbor", "RFC 8152 C.7.1.  Public Keys");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_7_2() {
    _test_case.begin("RFC 8152 C.7");

    cbor_array* root = new cbor_array();
    {
        cbor_map* key = new cbor_map();

        *key << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(cose_kty_t::cose_kty_ec2))
             << new cbor_pair(cose_key_lable_t::cose_lable_kid, new cbor_data(str2bin("meriadoc.brandybuck@buckland.example")))
             << new cbor_pair(cose_key_lable_t::cose_ec_crv, new cbor_data(cose_ec_curve_t::cose_ec_p256))
             << new cbor_pair(cose_key_lable_t::cose_ec_x, new cbor_data(base16_decode("65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d")))
             << new cbor_pair(cose_key_lable_t::cose_ec_y, new cbor_data(base16_decode("1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c")))
             << new cbor_pair(cose_key_lable_t::cose_ec_d, new cbor_data(base16_decode("aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf")));

        *root << key;
    }
    {
        cbor_map* key = new cbor_map();

        *key << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(cose_kty_t::cose_kty_ec2))
             << new cbor_pair(cose_key_lable_t::cose_lable_kid, new cbor_data(str2bin("11")))
             << new cbor_pair(cose_key_lable_t::cose_ec_crv, new cbor_data(cose_ec_curve_t::cose_ec_p256))
             << new cbor_pair(cose_key_lable_t::cose_ec_x, new cbor_data(base16_decode("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff")))
             << new cbor_pair(cose_key_lable_t::cose_ec_y, new cbor_data(base16_decode("20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e")))
             << new cbor_pair(cose_key_lable_t::cose_ec_d, new cbor_data(base16_decode("57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3")));

        *root << key;
    }
    {
        cbor_map* key = new cbor_map();

        *key
            << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(cose_kty_t::cose_kty_ec2))
            << new cbor_pair(cose_key_lable_t::cose_lable_kid, new cbor_data(str2bin("bilbo.baggins@hobbiton.example")))
            << new cbor_pair(cose_key_lable_t::cose_ec_crv, new cbor_data(cose_ec_curve_t::cose_ec_p521))
            << new cbor_pair(
                   cose_key_lable_t::cose_ec_x,
                   new cbor_data(base16_decode(
                       "0072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad")))
            << new cbor_pair(
                   cose_key_lable_t::cose_ec_y,
                   new cbor_data(base16_decode(
                       "01dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1d9475")))
            << new cbor_pair(cose_key_lable_t::cose_ec_d, new cbor_data(base16_decode("00085138ddabf5ca975f5860f91a08e91d6d5f9a76ad4018766a476680b55cd339e8ab6c"
                                                                                      "72b5facdb2a2a50ac25bd086647dd3e2e6e99e84ca2c3609fdf177feb26d")));

        *root << key;
    }
    {
        cbor_map* key = new cbor_map();

        *key << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(cose_kty_t::cose_kty_symm))
             << new cbor_pair(cose_key_lable_t::cose_lable_kid, new cbor_data(str2bin("our-secret")))
             << new cbor_pair(cose_key_lable_t::cose_symm_k, new cbor_data(base16_decode("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188")));

        *root << key;
    }
    {
        cbor_map* key = new cbor_map();

        *key << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(cose_kty_t::cose_kty_ec2))
             << new cbor_pair(cose_key_lable_t::cose_ec_crv, new cbor_data(cose_ec_curve_t::cose_ec_p256))
             << new cbor_pair(cose_key_lable_t::cose_lable_kid, new cbor_data(str2bin("peregrin.took@tuckborough.example")))
             << new cbor_pair(cose_key_lable_t::cose_ec_x, new cbor_data(base16_decode("98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280")))
             << new cbor_pair(cose_key_lable_t::cose_ec_y, new cbor_data(base16_decode("f01400b089867804b8e9fc96c3932161f1934f4223069170d924b7e03bf822bb")))
             << new cbor_pair(cose_key_lable_t::cose_ec_d, new cbor_data(base16_decode("02d1f7e6f26c43d4868d87ceb2353161740aacf1f7163647984b522a848df1c3")));

        *root << key;
    }
    {
        cbor_map* key = new cbor_map();

        *key << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(cose_kty_t::cose_kty_symm))
             << new cbor_pair(cose_key_lable_t::cose_lable_kid, new cbor_data(str2bin("our-secret2")))
             << new cbor_pair(cose_key_lable_t::cose_symm_k, new cbor_data(base16_decode("849b5786457c1491be3a76dcea6c4271")));

        *root << key;
    }
    {
        cbor_map* key = new cbor_map();

        *key << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(cose_kty_t::cose_kty_symm))
             << new cbor_pair(cose_key_lable_t::cose_lable_kid, new cbor_data(str2bin("018c0ae5-4d9b-471b-bfd6-eef314bc7037")))
             << new cbor_pair(cose_key_lable_t::cose_symm_k, new cbor_data(base16_decode("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188")));

        *root << key;
    }

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    do_test_cose_example(cose_handle, &rfc8152_privkeys, root, "rfc8152_c_7_2.cbor", "RFC 8152 C.7.2.  Private Keys");
    cose.close(cose_handle);

    root->release();
}

void do_test_cbor_key(const char* file, const char* text) {
    _test_case.begin("CBOR encoded keys - order not guaranteed");
    return_t ret = errorcode_t::success;
    const OPTION& option = _cmdline->value();
    crypto_key key;
    cbor_web_key cwk;

    binary_t cbor;
    file_stream fs;

    ret = fs.open(file);
    if (errorcode_t::success == ret) {
        fs.begin_mmap();

        byte_t* file_contents = fs.data();
        size_t file_size = fs.size();
        cbor.insert(cbor.end(), file_contents, file_contents + file_size);

        ret = cwk.load(&key, cbor);
        key.for_each(dump_crypto_key, nullptr);
        _test_case.test(ret, __FUNCTION__, "step.load %s", text ? text : "");

        binary_t cbor_written;
        ret = cwk.write(&key, cbor_written);
        _test_case.test(ret, __FUNCTION__, "step.write %s", text ? text : "");

        if (option.verbose) {
            test_case_notimecheck notimecheck(_test_case);

            _logger->hdump("from file", cbor, 32);
            _logger->hdump("from cwk", cbor_written, 32);

            basic_stream diagnostic;
            cbor_reader reader;
            cbor_reader_context_t* handle = nullptr;

            reader.open(&handle);
            reader.parse(handle, cbor);
            reader.publish(handle, &diagnostic);

            _logger->writeln("from file\n%s", diagnostic.c_str());

            reader.parse(handle, cbor_written);
            reader.publish(handle, &diagnostic);

            _logger->writeln("from cwk\n%s", diagnostic.c_str());

            reader.close(handle);
        }
    }
    _test_case.test(ret, __FUNCTION__, text ? text : "");
}

void test_rfc8152_read_cbor() {
    do_test_cbor_file("rfc8152_b.cbor", "RFC 8152 Appendix B.  Two Layers of Recipient Information");
    do_test_cbor_file("rfc8152_c_1_1.cbor", "RFC 8152 C.1.1.  Single Signature");
    do_test_cbor_file("rfc8152_c_1_2.cbor", "RFC 8152 C.1.2.  Multiple Signers");
    do_test_cbor_file("rfc8152_c_1_3.cbor", "RFC 8152 C.1.3.  Counter Signature");
    do_test_cbor_file("rfc8152_c_1_4.cbor", "RFC 8152 C.1.4.  Signature with Criticality");
    do_test_cbor_file("rfc8152_c_2_1.cbor", "RFC 8152 C.2.1.  Single ECDSA Signature");
    do_test_cbor_file("rfc8152_c_3_1.cbor", "RFC 8152 C.3.1.  Direct ECDH");
    do_test_cbor_file("rfc8152_c_3_2.cbor", "RFC 8152 C.3.2.  Direct Plus Key Derivation");
    do_test_cbor_file("rfc8152_c_3_3.cbor", "RFC 8152 C.3.3.  Counter Signature on Encrypted Content");
    do_test_cbor_file("rfc8152_c_3_4.cbor", "RFC 8152 C.3.4.  Encrypted Content with External Data");
    do_test_cbor_file("rfc8152_c_4_1.cbor", "RFC 8152 C.4.1.  Simple Encrypted Message");
    do_test_cbor_file("rfc8152_c_4_2.cbor", "RFC 8152 C.4.2.  Encrypted Message with a Partial IV");
    do_test_cbor_file("rfc8152_c_5_1.cbor", "RFC 8152 C.5.1.  Shared Secret Direct MAC");
    do_test_cbor_file("rfc8152_c_5_2.cbor", "RFC 8152 C.5.2.  ECDH Direct MAC");
    do_test_cbor_file("rfc8152_c_5_3.cbor", "RFC 8152 C.5.3.  Wrapped MAC");
    do_test_cbor_file("rfc8152_c_5_4.cbor", "RFC 8152 C.5.4.  Multi-Recipient MACed Message");
    do_test_cbor_file("rfc8152_c_6_1.cbor", "RFC 8152 C.6.1.  Shared Secret Direct MAC");
    do_test_cbor_file("rfc8152_c_7_1.cbor", "RFC 8152 C.7.1.  Public Keys");
    do_test_cbor_file("rfc8152_c_7_2.cbor", "RFC 8152 C.7.2.  Private Keys");
    do_test_cbor_file("rfc8778_a_1.cbor", "RFC 8778 A.1.  Example COSE Full Message Signature");
    do_test_cbor_file("rfc8778_a_2.cbor", "RFC 8778 A.2.  Example COSE_Sign1 Message");
    do_test_cbor_file("rfc9338_a_1_1.cbor", "RFC 9338 A.1.1.  Countersignature");
    do_test_cbor_file("rfc9338_a_2_1.cbor", "RFC 9338 A.2.1.  Countersignature");
    do_test_cbor_file("rfc9338_a_3_1.cbor", "RFC 9338 A.3.1.  Countersignature on Encrypted Content");
    do_test_cbor_file("rfc9338_a_4_1.cbor", "RFC 9338 A.4.1.  Countersignature on Encrypted Content");
    do_test_cbor_file("rfc9338_a_5_1.cbor", "RFC 9338 A.5.1.  Countersignature on MAC Content");
    do_test_cbor_file("rfc9338_a_6_1.cbor", "RFC 9338 A.6.1.  Countersignature on MAC0 Content");  // typo ? not 159 bytes, but 139 bytes
    do_test_cbor_key("rfc8152_c_7_1.cbor", "RFC 8152 C.7.1.  Public Keys");
    do_test_cbor_key("rfc8152_c_7_2.cbor", "RFC 8152 C.7.2.  Private Keys");
}

void test_jose_from_cwk() {
    _test_case.begin("crypto_key");
    const OPTION& option = _cmdline->value();

    // load keys from CBOR
    cbor_web_key cwk;
    crypto_key pubkey;
    cwk.load_file(&pubkey, key_ownspec, "rfc8152_c_7_1.cbor");
    pubkey.for_each(dump_crypto_key, nullptr);
    crypto_key privkey;
    cwk.load_file(&privkey, key_ownspec, "rfc8152_c_7_2.cbor");
    privkey.for_each(dump_crypto_key, nullptr);

    // dump keys JWK formatted
    json_web_key jwk;
    size_t size = 0;
    basic_stream json;
    jwk.write(&privkey, &json, 1);
    if (option.verbose) {
        _logger->writeln("JWK from CBOR key\n%s", json.c_str());
    }
    basic_stream pem;
    jwk.write_pem(&pubkey, &pem);
    if (option.verbose) {
        _logger->writeln("PEM (public)\n%s", pem.c_str());
    }
    jwk.write_pem(&privkey, &pem);
    if (option.verbose) {
        _logger->writeln("PEM (private)\n%s", pem.c_str());
    }

    const EVP_PKEY* pkey = nullptr;
    std::string kid;
    pkey = privkey.select(kid, crypt_sig_t::sig_es512);
    _test_case.assert(kid == "bilbo.baggins@hobbiton.example", __FUNCTION__, "select key from CWK where type is es512");
    pkey = privkey.select(kid, crypt_sig_t::sig_es256);
    _test_case.assert(kid == "11", __FUNCTION__, "select key from CWK where type is es256");  // alphabetic order...

    _test_case.reset_time();

    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    cbor_object_signing_encryption cose;
    cose_context_t* handle = nullptr;
    binary_t signature;
    basic_stream bs;
    bool result = true;
    constexpr char input[] = "wild wild world";
    cose.open(&handle);
    std::list<cose_alg_t> algs;
    algs.push_back(cose_alg_t::cose_es256);
    algs.push_back(cose_alg_t::cose_es512);
    ret = cose.sign(handle, &privkey, algs, str2bin(input), signature);
    _test_case.test(ret, __FUNCTION__, "sign");
    if (option.verbose) {
        test_case_notimecheck notimecheck(_test_case);

        dump_memory(signature, &bs);
        _logger->writeln("signature\n%s", bs.c_str());
        _logger->writeln("cbor\n%s", base16_encode(signature).c_str());

        basic_stream diagnostic;
        cbor_reader reader;
        cbor_reader_context_t* reader_handle = nullptr;
        reader.open(&reader_handle);
        reader.parse(reader_handle, signature);
        reader.publish(reader_handle, &diagnostic);
        reader.close(reader_handle);
        _logger->writeln("diagnostic\n%s", diagnostic.c_str());
    }
    ret = cose.verify(handle, &pubkey, signature, result);
    _test_case.test(ret, __FUNCTION__, "verify");
    cose.close(handle);
}
