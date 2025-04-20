#include "sample.hpp"

const test_vector_rfc7539_t test_vector_rfc7539[] = {
    {
        "RFC 7539/8439 2.4",
        "chacha20",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        1,
        "000000000000004a00000000",
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
        "",
        "",
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e"
        "088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d",
    },
    {
        "RFC 7539/8439 2.8",
        "chacha20-poly1305",
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        7,
        "40 41 42 43 44 45 46 47",
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
        "50515253c0c1c2c3c4c5c6c7",
        "1a:e1:0b:59:4f:09:e2:6a:7e:90:2e:cb:d0:60:06:91",
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803ae"
        "e328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
    },
};

const size_t sizeof_test_vector_rfc7539 = RTL_NUMBER_OF(test_vector_rfc7539);
