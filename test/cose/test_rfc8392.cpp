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

void test_cwt_rfc8392() {
    _test_case.begin("CWT");

    // A.1.  Example CWT Claims Set
    constexpr char claim[] =
        "a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9"
        "f007420b71";
    // A.2.1.  128-Bit Symmetric Key
    constexpr char symm128[] = "a42050231f4c4d4d3051fdc2ec0a3851d5b3830104024c53796d6d6574726963313238030a";
    // A.2.2.  256-Bit Symmetric Key
    constexpr char symm256[] = "a4205820403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d795693880104024c53796d6d6574726963323536030a";
    // A.2.3.  Elliptic Curve Digital Signature Algorithm (ECDSA) P-256 256-Bit COSE Key
    constexpr char ec256p[] =
        "a72358206c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c1922582060f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b921582014"
        "3329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f2001010202524173796d6d657472696345434453413235360326";
    // A.3.  Example Signed CWT
    constexpr char cwt_signed[] =
        "d28443a10126a104524173796d6d657472696345434453413235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c69676874"
        "2e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7158405427c1ff28d23fbad1f29c4c7c6a555e601d6fa29f9179bc3d7438bacaca5acd08c8d4d4f96131"
        "680c429a01f85951ecee743a52b9b63632c57209120e1c9e30";
    // A.4.  Example MACed CWT
    constexpr char cwt_maced[] =
        "d83dd18443a10104a1044c53796d6d65747269633235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e657861"
        "6d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7148093101ef6d789200";
    // A.5.  Example Encrypted CWT
    constexpr char cwt_encrypted[] =
        "d08343a1010aa2044c53796d6d6574726963313238054d99a0d7846e762c49ffe8a63e0b5858b918a11fd81e438b7f973d9e2e119bcb22424ba0f38a80f27562f400ee1d0d6c0fdb559c02"
        "421fd384fc2ebe22d7071378b0ea7428fff157444d45f7e6afcda1aae5f6495830c58627087fc5b4974f319a8707a635dd643b";
    // A.6.  Example Nested CWT
    constexpr char cwt_nested[] =
        "d08343a1010aa2044c53796d6d6574726963313238054d4a0694c0e69ee6b5956655c7b258b7f6b0914f993de822cc47e5e57a188d7960b528a747446fe12f0e7de05650dec74724366763"
        "f167a29c002dfd15b34d8993391cf49bc91127f545dba8703d66f5b7f1ae91237503d371e6333df9708d78c4fb8a8386c8ff09dc49af768b23179deab78d96490a66d5724fb33900c60799"
        "d9872fac6da3bdb89043d67c2a05414ce331b5b8f1ed8ff7138f45905db2c4d5bc8045ab372bff142631610a7e0f677b7e9b0bc73adefdcee16d9d5d284c616abeab5d8c291ce0";
    // A.7.  Example MACed CWT with a Floating-Point Value
    constexpr char cwt_maced_fp[] = "d18443a10104a1044c53796d6d65747269633235364ba106fb41d584367c20000048b8816f34c0542892";

    return_t ret = errorcode_t::success;
    const OPTION& option = _cmdline->value();
    crypto_key key;
    cbor_web_key cwk;
    cwk.load_b16(&key, symm128);
    cwk.load_b16(&key, symm256);
    cwk.load_b16(&key, ec256p);

    key.for_each(dump_crypto_key, nullptr);

    bool result = false;
    cose_context_t* handle = nullptr;
    cbor_object_signing_encryption cose;
    binary_t output;

    cose.open(&handle);
    if (option.verbose) {
        cose.set(handle, cose_flag_t::cose_flag_allow_debug);
    }
    ret = cose.verify(handle, &key, base16_decode(cwt_signed), result);
    _test_case.test(ret, __FUNCTION__, "RFC 8392 A.3.  Example Signed CWT");
    ret = cose.verify(handle, &key, base16_decode(cwt_maced), result);
    _test_case.test(ret, __FUNCTION__, "RFC 8392 A.4.  Example MACed CWT");
    ret = cose.decrypt(handle, &key, base16_decode(cwt_encrypted), output, result);
    _test_case.test(ret, __FUNCTION__, "RFC 8392 A.5.  Example Encrypted CWT");
    ret = cose.process(handle, &key, base16_decode(cwt_nested), output);
    _test_case.test(ret, __FUNCTION__, "RFC 8392 A.6.  Example Nested CWT");
    ret = cose.process(handle, &key, base16_decode(cwt_maced_fp), output);
    _test_case.test(ret, __FUNCTION__, "RFC 8392 A.7.  Example MACed CWT with a Floating-Point Value");
    cose.close(handle);
}
