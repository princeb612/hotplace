#include "sample.hpp"

// https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/KAT_AES.zip

const test_vector_nist_cavp_blockcipher_t test_vector_nist_cavp_blockcipher[] = {
    {
        "CBCGFSbox128.rsp, count = 0",
        "aes-128-cbc",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "f34481ec3cc627bacd5dc3fb08f273e6",
        "0336763e966d92595a567cc9ce537f5e",
    },
    {
        "CBCGFSbox192.rsp, count = 0",
        "aes-192-cbc",
        "000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
        "1b077a6af4b7f98229de786d7516b639",
        "275cfc0413d8ccb70513c3859b1d0f72",
    },
    {
        "CBCGFSbox256.rsp, count = 0",
        "aes-256-cbc",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
        "014730f80ac625fe84f026c60bfd547d",
        "5c9d844ed46f9885085e5d6a4f94c7d7",
    },

    {
        "CFB128GFSbox128.rsp, count = 0",
        "aes-128-cfb",
        "00000000000000000000000000000000",
        "f34481ec3cc627bacd5dc3fb08f273e6",
        "00000000000000000000000000000000",
        "0336763e966d92595a567cc9ce537f5e",
    },
    {
        "CFB128GFSbox192.rsp, count = 0",
        "aes-192-cfb",
        "000000000000000000000000000000000000000000000000",
        "1b077a6af4b7f98229de786d7516b639",
        "00000000000000000000000000000000",
        "275cfc0413d8ccb70513c3859b1d0f72",
    },
    {
        "CFB128GFSbox256.rsp, count = 0",
        "aes-256-cfb",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "014730f80ac625fe84f026c60bfd547d",
        "00000000000000000000000000000000",
        "5c9d844ed46f9885085e5d6a4f94c7d7",
    },

#if 0
    {
        "CFB1GFSbox128.rsp, count = 0",
        "aes-128-cfb1",
        "00000000000000000000000000000000",
        "f34481ec3cc627bacd5dc3fb08f273e6",
        "00",
        "00",
    },
    {
        "CFB1GFSbox192.rsp, count = 0",
        "aes-192-cfb1",
        "000000000000000000000000000000000000000000000000",
        "1b077a6af4b7f98229de786d7516b639",
        "00",
        "00",
    },
    {
        "CFB1GFSbox256.rsp, count = 0",
        "aes-256-cfb1",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "014730f80ac625fe84f026c60bfd547d",
        "00",
        "00",
    },
#endif

    {
        "CFB8GFSbox128.rsp, count = 0",
        "aes-128-cfb8",
        "00000000000000000000000000000000",
        "f34481ec3cc627bacd5dc3fb08f273e6",
        "00",
        "03",
    },
    {
        "CFB8GFSbox192.rsp, count = 0",
        "aes-192-cfb8",
        "000000000000000000000000000000000000000000000000",
        "1b077a6af4b7f98229de786d7516b639",
        "00",
        "27",
    },
    {
        "CFB8GFSbox256.rsp, count = 0",
        "aes-256-cfb8",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "014730f80ac625fe84f026c60bfd547d",
        "00",
        "5c",
    },

    {
        "ECBGFSbox128.rsp, count = 0",
        "aes-128-ecb",
        "00000000000000000000000000000000",
        "",
        "f34481ec3cc627bacd5dc3fb08f273e6",
        "0336763e966d92595a567cc9ce537f5e",
    },
    {
        "ECBGFSbox192.rsp, count = 0",
        "aes-192-ecb",
        "000000000000000000000000000000000000000000000000",
        "",
        "1b077a6af4b7f98229de786d7516b639",
        "275cfc0413d8ccb70513c3859b1d0f72",
    },
    {
        "ECBGFSbox256.rsp, count = 0",
        "aes-256-ecb",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "",
        "014730f80ac625fe84f026c60bfd547d",
        "5c9d844ed46f9885085e5d6a4f94c7d7",
    },

    {
        "OFBGFSbox128.rsp, count = 0",
        "aes-128-ofb",
        "00000000000000000000000000000000",
        "f34481ec3cc627bacd5dc3fb08f273e6",
        "00000000000000000000000000000000",
        "0336763e966d92595a567cc9ce537f5e",
    },
    {
        "OFBGFSbox192.rsp, count = 0",
        "aes-192-ofb",
        "000000000000000000000000000000000000000000000000",
        "1b077a6af4b7f98229de786d7516b639",
        "00000000000000000000000000000000",
        "275cfc0413d8ccb70513c3859b1d0f72",
    },
    {
        "OFBGFSbox256.rsp, count = 0",
        "aes-256-ofb",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "014730f80ac625fe84f026c60bfd547d",
        "00000000000000000000000000000000",
        "5c9d844ed46f9885085e5d6a4f94c7d7",
    },
};

const size_t sizeof_test_vector_nist_cavp_blockcipher = RTL_NUMBER_OF(test_vector_nist_cavp_blockcipher);
