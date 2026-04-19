/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/crypto/sample.hpp>

void test_transcript_hash() {
    _test_case.begin("test");

    openssl_hash hash;
    hash_context_t* handle = nullptr;

    const char* stream1 = "client hello";
    const char* stream2 = "server hello";

    // case1 update(stream1).update(stream2).finalize(hash2)
    binary_t case1_hash_stream2;
    {
        hash.open(&handle, "sha256");
        hash.init(handle);
        hash.update(handle, (byte_t*)stream1, strlen(stream1));
        hash.update(handle, (byte_t*)stream2, strlen(stream2));
        hash.finalize(handle, case1_hash_stream2);
        hash.close(handle);
        _logger->hdump("stream1+stream2", case1_hash_stream2);
    }

    // case2 update(stream1, hash1).update(stream2, hash2)
    binary_t case2_hash_stream1;
    binary_t case2_hash_stream2;
    {
        hash.open(&handle, "sha256");
        hash.init(handle);
        hash.update(handle, (byte_t*)stream1, strlen(stream1), case2_hash_stream1);
        hash.update(handle, (byte_t*)stream2, strlen(stream2), case2_hash_stream2);
        hash.close(handle);
        _logger->hdump("stream1", case2_hash_stream1);
        _logger->hdump("stream1+stream2", case2_hash_stream2);
    }
    _test_case.assert(case2_hash_stream2 == case1_hash_stream2, __FUNCTION__, "transcript_hash");

    // case3 digest(stream1, hash1).digest(stream2, hash2)
    binary_t case3_hash_stream1;
    binary_t case3_hash_stream2;
    {
        transcript_hash_builder builder;
        auto hash = builder.set(sha2_256).build();
        if (hash) {
            hash->digest((byte_t*)stream1, strlen(stream1), case3_hash_stream1);
            hash->digest((byte_t*)stream2, strlen(stream2), case3_hash_stream2);
            hash->release();
        }
        _logger->hdump("stream1", case3_hash_stream1);
        _logger->hdump("stream1+stream2", case3_hash_stream2);
    }
    _test_case.assert(case3_hash_stream2 == case1_hash_stream2, __FUNCTION__, "transcript_hash");
}

void testcase_transcript_hash() { test_transcript_hash(); }
