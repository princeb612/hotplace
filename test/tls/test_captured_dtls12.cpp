/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 * @remarks
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include "sample.hpp"

// dtls12/dtls12.pcapng
pcap_testvector capture_dtls12[] = {
    {
        // C->S, epoch 0 seq 0 - client_hello (fragment)
        from_client,
        "client_hello (fragment)",
        "16 fe ff 00 00 00 00 00 00 00 00 00 c3 01 00 00"
        "bd 00 00 00 00 00 00 00 b7 fe fd 9f c7 e2 53 87"
        "0b 87 fa a8 21 b7 76 16 c4 c3 6f 60 6f 82 ed 8c"
        "d7 86 d7 0a f2 d4 23 6e 99 2e 07 00 00 00 36 c0"
        "2c c0 30 00 9f cc a9 cc a8 cc aa c0 2b c0 2f 00"
        "9e c0 24 c0 28 00 6b c0 23 c0 27 00 67 c0 0a c0"
        "14 00 39 c0 09 c0 13 00 33 00 9d 00 9c 00 3d 00"
        "3c 00 35 00 2f 01 00 00 5d ff 01 00 01 00 00 0b"
        "00 04 03 00 01 02 00 0a 00 0c 00 0a 00 1d 00 17"
        "00 1e 00 19 00 18 00 23 00 00 00 16 00 00 00 17"
        "00 00 00 0d 00 30 00 2e 04 03 05 03 06 03 08 07"
        "08 08 08 1a 08 1b 08 1c 08 09 08 0a 08 0b 08 04"
        "08 05 08 06 04 01 05 01 06 01 03 03 03 01 03 02",
    },
    {
        // C->S, epoch 0 seq 1 - client_hello (reassembled)
        from_client,
        "client_hello (reassembled)",
        "16 fe ff 00 00 00 00 00 00 00 01 00 12 01 00 00"
        "bd 00 00 00 00 b7 00 00 06 04 02 05 02 06 02",
    },
    {
        // S->C, epoch 0 seq 0 - hello_verify_request
        from_server,
        "hello_verify_request",
        "16 fe ff 00 00 00 00 00 00 00 00 00 23 03 00 00"
        "17 00 00 00 00 00 00 00 17 fe ff 14 d8 32 1d 16"
        "e2 72 e5 3c bc 26 77 2d ff 69 a2 56 ed cd cc 0a",
    },
    {
        // C->S, epoch 0 seq 2 - client_hello (fragment)
        from_client,
        "client_hello (fragment)",
        "16 fe ff 00 00 00 00 00 00 00 02 00 c3 01 00 00"
        "d1 00 01 00 00 00 00 00 b7 fe fd 9f c7 e2 53 87"
        "0b 87 fa a8 21 b7 76 16 c4 c3 6f 60 6f 82 ed 8c"
        "d7 86 d7 0a f2 d4 23 6e 99 2e 07 00 14 d8 32 1d"
        "16 e2 72 e5 3c bc 26 77 2d ff 69 a2 56 ed cd cc"
        "0a 00 36 c0 2c c0 30 00 9f cc a9 cc a8 cc aa c0"
        "2b c0 2f 00 9e c0 24 c0 28 00 6b c0 23 c0 27 00"
        "67 c0 0a c0 14 00 39 c0 09 c0 13 00 33 00 9d 00"
        "9c 00 3d 00 3c 00 35 00 2f 01 00 00 5d ff 01 00"
        "01 00 00 0b 00 04 03 00 01 02 00 0a 00 0c 00 0a"
        "00 1d 00 17 00 1e 00 19 00 18 00 23 00 00 00 16"
        "00 00 00 17 00 00 00 0d 00 30 00 2e 04 03 05 03"
        "06 03 08 07 08 08 08 1a 08 1b 08 1c 08 09 08 0a",
    },
    {
        // C->S, epoch 0 seq 3 - client_hello (reassembled)
        from_client,
        "client_hello (reassembled)",
        "16 fe ff 00 00 00 00 00 00 00 03 00 26 01 00 00"
        "d1 00 01 00 00 b7 00 00 1a 08 0b 08 04 08 05 08"
        "06 04 01 05 01 06 01 03 03 03 01 03 02 04 02 05"
        "02 06 02",
    },
    {
        // S->C, epoch 0 seq 1 - server_hello
        // S->C, epoch 0 seq 2 - certificate (fragment)
        from_server,
        "server_hello, certificate (fragment)",
        "16 fe fd 00 00 00 00 00 00 00 01 00 4d 02 00 00"
        "41 00 01 00 00 00 00 00 41 fe fd f0 21 fa a3 69"
        "c3 88 f4 80 2c 34 4d 67 cb 23 d9 6e 79 b6 85 68"
        "d2 ad ee 45 b0 0c cc 36 a7 7f 8a 00 c0 27 00 00"
        "19 ff 01 00 01 00 00 0b 00 04 03 00 01 02 00 23"
        "00 00 00 16 00 00 00 17 00 00 16 fe fd 00 00 00"
        "00 00 00 00 02 00 69 0b 00 03 66 00 02 00 00 00"
        "00 00 5d 00 03 63 00 03 60 30 82 03 5c 30 82 02"
        "44 a0 03 02 01 02 02 14 63 a6 71 10 79 d6 a6 48"
        "59 da 67 a9 04 e8 e3 5f e2 03 a3 26 30 0d 06 09"
        "2a 86 48 86 f7 0d 01 01 0b 05 00 30 59 31 0b 30"
        "09 06 03 55 04 06 13 02 4b 52 31 0b 30 09 06 03"
        "55 04 08 0c 02 47 47 31 0b 30 09 06 03 55 04 07",
    },
    {
        // S->C, epoch 0 seq 3 - certificate (fragment)
        from_server,
        "certificate (fragment)",
        "16 fe fd 00 00 00 00 00 00 00 03 00 c3 0b 00 03"
        "66 00 02 00 00 5d 00 00 b7 0c 02 59 49 31 0d 30"
        "0b 06 03 55 04 0a 0c 04 54 65 73 74 31 0d 30 0b"
        "06 03 55 04 0b 0c 04 54 65 73 74 31 12 30 10 06"
        "03 55 04 03 0c 09 54 65 73 74 20 52 6f 6f 74 30"
        "1e 17 0d 32 34 30 38 32 39 30 36 32 37 31 37 5a"
        "17 0d 32 35 30 38 32 39 30 36 32 37 31 37 5a 30"
        "54 31 0b 30 09 06 03 55 04 06 13 02 4b 52 31 0b"
        "30 09 06 03 55 04 08 0c 02 47 47 31 0b 30 09 06"
        "03 55 04 07 0c 02 59 49 31 0d 30 0b 06 03 55 04"
        "0a 0c 04 54 65 73 74 31 0d 30 0b 06 03 55 04 0b"
        "0c 04 54 65 73 74 31 0d 30 0b 06 03 55 04 03 0c"
        "04 54 65 73 74 30 82 01 22 30 0d 06 09 2a 86 48",
    },
    {
        // S->C, epoch 0 seq 4 - certificate (fragment)
        from_server,
        "certificate (fragment)",
        "16 fe fd 00 00 00 00 00 00 00 04 00 c3 0b 00 03"
        "66 00 02 00 01 14 00 00 b7 86 f7 0d 01 01 01 05"
        "00 03 82 01 0f 00 30 82 01 0a 02 82 01 01 00 ad"
        "9a 29 67 5f f3 a4 79 b4 c6 e6 32 73 d8 d7 ed 88"
        "94 15 83 e4 31 00 04 6c b5 8c ac 87 ab 74 44 13"
        "76 ca 0b 74 29 40 9e 97 2a 01 d7 8b 46 26 6e 19"
        "35 4d c0 d3 b5 ea 0e 93 3a 06 e8 e5 85 b5 27 05"
        "63 db 28 b8 92 da 5a 14 39 0f da 68 6d 6f 0a fb"
        "52 dc 08 0f 54 d3 e4 a2 28 9d a0 71 50 82 e0 db"
        "ca d1 94 dd 42 98 3a 09 33 a8 d9 ef fb d2 35 43"
        "b1 22 a2 be 41 6d ba 91 dc 0b 31 4e 88 f9 4d 9c"
        "61 2d ec b2 13 0a c2 91 8e a2 d6 e9 40 b9 32 b9"
        "80 8f b3 18 a3 33 13 23 d5 d0 7e d9 d0 7f 93 e0",
    },
    {
        // S->C, epoch 0 seq 5 - certificate (fragment)
        from_server,
        "certificate (fragment)",
        "16 fe fd 00 00 00 00 00 00 00 05 00 c3 0b 00 03"
        "66 00 02 00 01 cb 00 00 b7 2d 4d 90 c5 58 24 56"
        "d5 c9 10 13 4a b2 99 23 7d 34 b9 8e 97 19 69 6f"
        "ce c6 3f d6 17 a7 d2 43 e0 36 cb 51 7b 2f 18 8b"
        "c2 33 f8 57 cf d1 61 0b 7c ed 37 35 e3 13 7a 24"
        "2e 77 08 c2 e3 d9 e6 17 d3 a5 c6 34 5a da 86 a7"
        "f8 02 36 1d 66 63 cf e9 c0 3d 82 fb 39 a2 8d 92"
        "01 4a 83 cf e2 76 3d 87 02 03 01 00 01 a3 21 30"
        "1f 30 1d 06 03 55 1d 11 04 16 30 14 82 12 74 65"
        "73 74 2e 70 72 69 6e 63 65 62 36 31 32 2e 70 65"
        "30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 03"
        "82 01 01 00 00 a5 f5 54 18 ab ad 36 38 c8 fc 0b"
        "66 60 dd 9f 75 9d 86 5b 79 2f ee 57 f1 79 1c 15",
    },
    {
        // S->C, epoch 0 seq 6 - certificate (fragment)
        from_server,
        "certificate (fragment)",
        "16 fe fd 00 00 00 00 00 00 00 06 00 c3 0b 00 03"
        "66 00 02 00 02 82 00 00 b7 a1 34 23 d0 1c a9 58"
        "51 a4 d0 08 f5 d8 f7 49 e9 c5 b5 65 91 51 2d 6d"
        "e4 3b 0e 77 02 1f 45 8e 34 e5 bb eb f6 9d df 4a"
        "40 60 21 b3 8e 16 33 3f f4 b6 90 d3 3c 34 ce e6"
        "d9 47 07 a7 57 14 0c f9 78 0b 36 72 a9 88 07 07"
        "93 b4 d7 fe 29 5e e8 41 37 20 a5 03 c7 97 cb 82"
        "ca db 14 e5 8b 96 1f a9 e9 20 3d 6b 25 ae f4 89"
        "4c 60 8d e9 14 33 47 4b 88 54 a2 47 19 81 c8 7b"
        "0e 32 52 2b 91 88 ad 0f 6d 73 30 8c 00 af d5 fc"
        "46 46 af 3a c2 17 89 ec c8 83 ae da e6 69 63 e0"
        "9c 84 22 c5 7a de e8 23 6b 53 9d 6f 94 d2 7f 5c"
        "be 1d 0c de 0e 07 0d 52 a5 43 8c e8 05 ef c0 ff",
    },
    {
        // S->C, epoch 0 seq 7 - certificate (reassembled)
        // S->C, epoch 0 seq 8 - server_key_exchange (fragment)
        from_server,
        "certificate (reassembled), server_key_exchange (fragment)",
        "16 fe fd 00 00 00 00 00 00 00 07 00 39 0b 00 03"
        "66 00 02 00 03 39 00 00 2d f0 73 fa dc 5a 51 4c"
        "24 09 65 45 7d ab 52 8b 7e 5d f0 fb de a7 3d 43"
        "c5 af 76 e3 6e f9 a1 dc 78 a2 bd 54 41 04 99 e5"
        "56 32 ba 02 fd 72 16 fe fd 00 00 00 00 00 00 00"
        "08 00 7d 0c 00 01 28 00 03 00 00 00 00 00 71 03"
        "00 1d 20 a4 a9 ba 02 fb 67 3f 13 6f bf af d8 43"
        "b9 c8 7a 23 20 d8 5e 20 de a7 d1 bc 41 59 76 68"
        "c9 e5 6a 08 04 01 00 81 f4 db ab 15 fc ab 02 6b"
        "85 ef 8d 5b 5d 17 a8 d7 e8 88 a2 fa 5a 8f 2e a9"
        "53 cc 65 89 9e 9b 35 45 63 15 92 99 92 6f 3d 06"
        "ce c0 0b 05 c0 d7 b1 73 c2 61 1c 65 8b f1 e0 bf"
        "68 e6 22 c4 c3 5f ff 90 70 3e 95 cc 0b e3 e6 ef",
    },
    {
        // S->C, epoch 0 seq 9 - server_key_exchange (reassembled)
        from_server,
        "server_key_exchange (reassembled)",
        "16 fe fd 00 00 00 00 00 00 00 09 00 c3 0c 00 01"
        "28 00 03 00 00 71 00 00 b7 81 36 3e 53 1e c2 40"
        "e5 2a 99 11 79 bd 23 62 29 df d4 ba 03 7f e4 5c"
        "6b 89 4f c0 0e f5 12 68 5f bf c4 54 f1 9f 91 db"
        "0d 58 75 f9 29 bf 8f b1 90 a2 84 0d 4a 6c 04 ad"
        "ea 1c 35 c6 b1 8f c4 49 e4 31 d9 dc 36 9a 81 ae"
        "db 28 cf 33 1b bf c8 23 b7 c7 11 c8 cf f6 69 69"
        "3c 21 0c 1b 58 73 25 39 76 dc 33 be 71 9e 28 cb"
        "df 28 e8 ca df ac 64 d6 c2 09 68 cd 9f d9 0f 8a"
        "f7 99 dd f8 93 01 19 68 7b e8 89 f5 c5 e7 0b 27"
        "18 8b 62 17 5d 7b 13 c2 4a 64 9c 38 46 56 c3 11"
        "3b 41 4b a5 26 20 df e0 a8 6d f9 72 31 fe 95 da"
        "a9 f3 a6 a1 54 e3 74 e1 7b 00 54 b7 eb 8e cc 5e",
    },
    {
        // S->C, epoch 0 seq 10 - server_hello_done
        from_server,
        "server_hello_done",
        "16 fe fd 00 00 00 00 00 00 00 0a 00 0c 0e 00 00"
        "00 00 04 00 00 00 00 00 00",
    },
    {
        // C->S, epoch 0 seq 4 - client_key_exchange
        // C->S, epoch 0 seq 5 - change_cipher_spec
        // C->S, epoch 1 seq 0 - finished
        from_client,
        "client_key_exchange, change_cipher_spec, finished",
        "16 fe fd 00 00 00 00 00 00 00 04 00 2d 10 00 00"
        "21 00 02 00 00 00 00 00 21 20 50 42 a8 d6 b5 bb"
        "fe 9a 7a d0 69 fc 48 e4 59 d5 c2 be f4 c5 f2 15"
        "3f 31 df 94 de 89 03 2e f9 57 14 fe fd 00 00 00"
        "00 00 00 00 05 00 01 01 16 fe fd 00 01 00 00 00"
        "00 00 00 00 50 41 e2 f4 6b 71 97 6e a4 73 76 92"
        "a1 a5 d7 d0 da 07 06 ef 1b 20 34 9a 04 83 f7 ae"
        "c6 8c 3a c6 6e 12 a3 d9 32 f3 07 a3 ef 74 cb e6"
        "6c 29 4e c9 c2 a0 12 4e e2 5c 98 69 c2 68 3b 10"
        "93 e2 cd ca 56 4a d7 d7 71 39 66 41 13 ec e4 96"
        "73 20 46 d5 6a",
    },
    {
        // S->C, epoch 0 seq 11 - new_session_ticket
        from_server,
        "new_session_ticket",
        "16 fe fd 00 00 00 00 00 00 00 0b 00 c2 04 00 00"
        "b6 00 05 00 00 00 00 00 b6 00 00 1c 20 00 b0 81"
        "91 12 df b7 f9 8c 99 db 44 56 fa 53 74 da 51 bb"
        "30 e2 f5 f2 f0 81 66 13 76 33 40 22 0b 0b f0 c5"
        "20 81 2b 62 f9 fa cc ac aa e8 08 a2 c2 c6 3e 70"
        "51 fc 62 e1 cb 88 8e d2 7c e3 d8 d1 ae f4 3f 01"
        "21 f4 37 a8 22 34 4d 66 7c d6 aa 16 70 28 f1 ca"
        "8e 66 71 8a fe 80 22 26 66 33 57 28 6d bd c5 04"
        "c1 66 02 d7 ac 0d 38 97 db f3 a3 77 73 4f 10 46"
        "ef f1 b9 9a e7 3b 84 fb 35 6a 44 d7 fd 94 7c b2"
        "78 1c b3 ff 90 be ad 1b 0b 5d 9e 95 db 51 35 e9"
        "3f 42 7f af a8 10 94 64 8f 2d e4 0d 30 ba c4 14"
        "a2 f2 63 3b 0d a5 6f b4 9f 52 81 e0 3b dd ac",
    },
    {
        // S->C, epoch 0 seq 12 - change_cipher_spec
        // S->C, epoch 1 seq 0 - encrypted_handshake message
        from_server,
        "change_cipher_spec, encrypted_handshake message",
        "14 fe fd 00 00 00 00 00 00 00 0c 00 01 01 16 fe"
        "fd 00 01 00 00 00 00 00 00 00 50 43 7b 0b 20 0b"
        "70 d3 a0 5e a6 31 8d af dc 14 5f ca 16 e2 05 03"
        "40 2a a2 0d 11 74 68 17 a5 60 f0 94 5b b7 a2 30"
        "e0 7e 05 a1 80 ba f8 1d 01 a0 62 ec 7c b4 95 da"
        "c3 99 95 90 59 4c f5 83 e3 cf 53 c8 16 6c 2d 8f"
        "70 4e 30 15 d9 f7 43 d7 3a 65 94",
    },
    {
        // C->S, epoch 1 seq 1 - application data
        from_client,
        "application data (hello)",
        "17 fe fd 00 01 00 00 00 00 00 01 00 40 22 6b 6d"
        "36 ec 69 1e 1b db 72 89 60 db 4f a2 c8 7c cd fb"
        "7b 52 24 83 e4 92 61 43 ac f2 2c 86 da 36 89 0a"
        "68 69 49 7e 64 b5 e7 ad 60 36 19 7e 6f 83 e2 70"
        "5e 07 9a 10 cd 3f d5 d3 cd 89 1f 94 c9",
    },
    {
        // C->S, epoch 1 seq 2 - encrypted alert
        from_client,
        "alert",
        "15 fe fd 00 01 00 00 00 00 00 02 00 40 7c 68 12"
        "83 f5 e2 60 f7 0b 87 c1 46 64 75 3f 16 a3 f7 c3"
        "22 16 21 41 a5 4b 0a e7 d6 7a e4 d3 d8 52 58 c7"
        "37 80 61 63 1e b3 1f 52 54 c8 06 37 60 22 f0 1b"
        "a7 fd 78 98 5e e3 dd d8 7b bd 94 e1 15",
    },
    {
        // S->C, epoch 1 seq 1 - encrypted alert
        from_server,
        "alert",
        "15 fe fd 00 01 00 00 00 00 00 01 00 40 1c 80 74"
        "c8 39 a7 19 3d 4e 1d 31 82 f0 5c f9 ca c3 1d 8b"
        "0f 0c 8c 3a 1a be 77 ee 4b e7 96 8d bf fb 32 ed"
        "06 d6 56 2d b9 e5 d9 62 23 fc c2 c0 cf 39 aa bd"
        "3e 38 e8 ab 29 14 61 64 11 28 45 a9 59",
    },
};

// dtls12/dtls12mtu1500.pcapng
pcap_testvector capture_dtls12mtu1500[] = {
    {
        from_client,
        "client_hello",
        "16 fe ff 00 00 00 00 00 00 00 00 00 c9 01 00 00"
        "bd 00 00 00 00 00 00 00 bd fe fd 72 d4 34 26 a5"
        "5a a0 09 5f f3 ac 7c 69 90 fe c0 00 8d ad 75 4d"
        "09 7c f7 04 58 cb 9e 49 b2 89 27 00 00 00 36 c0"
        "2c c0 30 00 9f cc a9 cc a8 cc aa c0 2b c0 2f 00"
        "9e c0 24 c0 28 00 6b c0 23 c0 27 00 67 c0 0a c0"
        "14 00 39 c0 09 c0 13 00 33 00 9d 00 9c 00 3d 00"
        "3c 00 35 00 2f 01 00 00 5d ff 01 00 01 00 00 0b"
        "00 04 03 00 01 02 00 0a 00 0c 00 0a 00 1d 00 17"
        "00 1e 00 19 00 18 00 23 00 00 00 16 00 00 00 17"
        "00 00 00 0d 00 30 00 2e 04 03 05 03 06 03 08 07"
        "08 08 08 1a 08 1b 08 1c 08 09 08 0a 08 0b 08 04"
        "08 05 08 06 04 01 05 01 06 01 03 03 03 01 03 02"
        "04 02 05 02 06 02",
    },
    {
        from_server,
        "hello verify request",
        "16 fe ff 00 00 00 00 00 00 00 00 00 23 03 00 00"
        "17 00 00 00 00 00 00 00 17 fe ff 14 b5 2e 26 56"
        "f9 71 3d 40 97 4c 59 ec e4 89 b3 2f 57 37 57 ce",
    },
    {
        from_client,
        "client hello",
        "16 fe ff 00 00 00 00 00 00 00 01 00 dd 01 00 00"
        "d1 00 01 00 00 00 00 00 d1 fe fd 72 d4 34 26 a5"
        "5a a0 09 5f f3 ac 7c 69 90 fe c0 00 8d ad 75 4d"
        "09 7c f7 04 58 cb 9e 49 b2 89 27 00 14 b5 2e 26"
        "56 f9 71 3d 40 97 4c 59 ec e4 89 b3 2f 57 37 57"
        "ce 00 36 c0 2c c0 30 00 9f cc a9 cc a8 cc aa c0"
        "2b c0 2f 00 9e c0 24 c0 28 00 6b c0 23 c0 27 00"
        "67 c0 0a c0 14 00 39 c0 09 c0 13 00 33 00 9d 00"
        "9c 00 3d 00 3c 00 35 00 2f 01 00 00 5d ff 01 00"
        "01 00 00 0b 00 04 03 00 01 02 00 0a 00 0c 00 0a"
        "00 1d 00 17 00 1e 00 19 00 18 00 23 00 00 00 16"
        "00 00 00 17 00 00 00 0d 00 30 00 2e 04 03 05 03"
        "06 03 08 07 08 08 08 1a 08 1b 08 1c 08 09 08 0a"
        "08 0b 08 04 08 05 08 06 04 01 05 01 06 01 03 03"
        "03 01 03 02 04 02 05 02 06 02",
    },
    {
        from_server,
        "server_hello, certificate, server key exchange, server hello done",
        "16 fe fd 00 00 00 00 00 00 00 01 00 4d 02 00 00"
        "41 00 01 00 00 00 00 00 41 fe fd c4 6f f0 c6 f8"
        "f2 0e 8f 16 05 31 f2 85 b0 1a fb 36 ae a5 f0 1b"
        "2b 9b de 69 aa 08 99 84 45 61 b0 00 c0 27 00 00"
        "19 ff 01 00 01 00 00 0b 00 04 03 00 01 02 00 23"
        "00 00 00 16 00 00 00 17 00 00 16 fe fd 00 00 00"
        "00 00 00 00 02 03 72 0b 00 03 66 00 02 00 00 00"
        "00 03 66 00 03 63 00 03 60 30 82 03 5c 30 82 02"
        "44 a0 03 02 01 02 02 14 63 a6 71 10 79 d6 a6 48"
        "59 da 67 a9 04 e8 e3 5f e2 03 a3 26 30 0d 06 09"
        "2a 86 48 86 f7 0d 01 01 0b 05 00 30 59 31 0b 30"
        "09 06 03 55 04 06 13 02 4b 52 31 0b 30 09 06 03"
        "55 04 08 0c 02 47 47 31 0b 30 09 06 03 55 04 07"
        "0c 02 59 49 31 0d 30 0b 06 03 55 04 0a 0c 04 54"
        "65 73 74 31 0d 30 0b 06 03 55 04 0b 0c 04 54 65"
        "73 74 31 12 30 10 06 03 55 04 03 0c 09 54 65 73"
        "74 20 52 6f 6f 74 30 1e 17 0d 32 34 30 38 32 39"
        "30 36 32 37 31 37 5a 17 0d 32 35 30 38 32 39 30"
        "36 32 37 31 37 5a 30 54 31 0b 30 09 06 03 55 04"
        "06 13 02 4b 52 31 0b 30 09 06 03 55 04 08 0c 02"
        "47 47 31 0b 30 09 06 03 55 04 07 0c 02 59 49 31"
        "0d 30 0b 06 03 55 04 0a 0c 04 54 65 73 74 31 0d"
        "30 0b 06 03 55 04 0b 0c 04 54 65 73 74 31 0d 30"
        "0b 06 03 55 04 03 0c 04 54 65 73 74 30 82 01 22"
        "30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03"
        "82 01 0f 00 30 82 01 0a 02 82 01 01 00 ad 9a 29"
        "67 5f f3 a4 79 b4 c6 e6 32 73 d8 d7 ed 88 94 15"
        "83 e4 31 00 04 6c b5 8c ac 87 ab 74 44 13 76 ca"
        "0b 74 29 40 9e 97 2a 01 d7 8b 46 26 6e 19 35 4d"
        "c0 d3 b5 ea 0e 93 3a 06 e8 e5 85 b5 27 05 63 db"
        "28 b8 92 da 5a 14 39 0f da 68 6d 6f 0a fb 52 dc"
        "08 0f 54 d3 e4 a2 28 9d a0 71 50 82 e0 db ca d1"
        "94 dd 42 98 3a 09 33 a8 d9 ef fb d2 35 43 b1 22"
        "a2 be 41 6d ba 91 dc 0b 31 4e 88 f9 4d 9c 61 2d"
        "ec b2 13 0a c2 91 8e a2 d6 e9 40 b9 32 b9 80 8f"
        "b3 18 a3 33 13 23 d5 d0 7e d9 d0 7f 93 e0 2d 4d"
        "90 c5 58 24 56 d5 c9 10 13 4a b2 99 23 7d 34 b9"
        "8e 97 19 69 6f ce c6 3f d6 17 a7 d2 43 e0 36 cb"
        "51 7b 2f 18 8b c2 33 f8 57 cf d1 61 0b 7c ed 37"
        "35 e3 13 7a 24 2e 77 08 c2 e3 d9 e6 17 d3 a5 c6"
        "34 5a da 86 a7 f8 02 36 1d 66 63 cf e9 c0 3d 82"
        "fb 39 a2 8d 92 01 4a 83 cf e2 76 3d 87 02 03 01"
        "00 01 a3 21 30 1f 30 1d 06 03 55 1d 11 04 16 30"
        "14 82 12 74 65 73 74 2e 70 72 69 6e 63 65 62 36"
        "31 32 2e 70 65 30 0d 06 09 2a 86 48 86 f7 0d 01"
        "01 0b 05 00 03 82 01 01 00 00 a5 f5 54 18 ab ad"
        "36 38 c8 fc 0b 66 60 dd 9f 75 9d 86 5b 79 2f ee"
        "57 f1 79 1c 15 a1 34 23 d0 1c a9 58 51 a4 d0 08"
        "f5 d8 f7 49 e9 c5 b5 65 91 51 2d 6d e4 3b 0e 77"
        "02 1f 45 8e 34 e5 bb eb f6 9d df 4a 40 60 21 b3"
        "8e 16 33 3f f4 b6 90 d3 3c 34 ce e6 d9 47 07 a7"
        "57 14 0c f9 78 0b 36 72 a9 88 07 07 93 b4 d7 fe"
        "29 5e e8 41 37 20 a5 03 c7 97 cb 82 ca db 14 e5"
        "8b 96 1f a9 e9 20 3d 6b 25 ae f4 89 4c 60 8d e9"
        "14 33 47 4b 88 54 a2 47 19 81 c8 7b 0e 32 52 2b"
        "91 88 ad 0f 6d 73 30 8c 00 af d5 fc 46 46 af 3a"
        "c2 17 89 ec c8 83 ae da e6 69 63 e0 9c 84 22 c5"
        "7a de e8 23 6b 53 9d 6f 94 d2 7f 5c be 1d 0c de"
        "0e 07 0d 52 a5 43 8c e8 05 ef c0 ff f0 73 fa dc"
        "5a 51 4c 24 09 65 45 7d ab 52 8b 7e 5d f0 fb de"
        "a7 3d 43 c5 af 76 e3 6e f9 a1 dc 78 a2 bd 54 41"
        "04 99 e5 56 32 ba 02 fd 72 16 fe fd 00 00 00 00"
        "00 00 00 03 01 34 0c 00 01 28 00 03 00 00 00 00"
        "01 28 03 00 1d 20 a8 7e 61 06 63 3a 42 0a c7 29"
        "44 19 57 8b de a2 e9 83 04 c9 75 a8 ab 44 47 1f"
        "ce c1 66 d3 1a 1b 08 04 01 00 91 ab 4c e4 97 1f"
        "90 76 85 8d 7f 0b 56 64 45 9c d0 ec 2c fe 41 10"
        "91 76 a7 69 81 8c 56 9a 44 8f 55 40 b2 2b 60 64"
        "c0 63 40 97 53 5f 38 c1 f5 b4 68 a6 6c 1a 4c 23"
        "e3 df 64 dc 18 77 d4 06 1d dc ab 97 2c d1 61 e3"
        "4d 17 19 5b 2f 77 0b ec 1c 68 bd 54 4d 60 d3 da"
        "1b 10 76 dc ad 99 4c ff 40 99 14 aa de 37 c6 ef"
        "2a 90 f7 5a ef 3d b6 99 63 70 e4 e4 d8 6f f9 6a"
        "1f 5f 13 28 0e b5 ab 8b d6 26 68 49 15 21 2b fb"
        "bf 53 19 53 d4 36 17 56 3e 57 b4 a8 d9 db 99 3f"
        "0d 8d f8 1c 3e af 32 23 45 73 49 11 d6 5c fa bf"
        "b3 af 1d 8c 05 2a 6c bb 74 c0 ea ad bb a1 e1 5c"
        "e9 23 50 b6 29 37 82 8d 88 b4 36 aa 5c f6 82 ab"
        "90 a7 30 e1 ce 92 02 2f 0d 5c 77 f1 b5 35 fb 48"
        "f2 73 ab e5 00 0d f1 ce 70 7a 04 bc 18 79 7c 65"
        "08 ca e5 f3 a0 6c 9e 61 1c 99 64 84 0f 19 c9 c5"
        "e3 dc 68 ba 1c 29 69 60 46 be 16 fe fd 00 00 00"
        "00 00 00 00 04 00 0c 0e 00 00 00 00 04 00 00 00"
        "00 00 00",
    },
    {
        from_client,
        "client key exchange, change cipher spec, finished",
        "16 fe fd 00 00 00 00 00 00 00 02 00 2d 10 00 00"
        "21 00 02 00 00 00 00 00 21 20 b7 6b 26 2b 2a c4"
        "b6 a4 05 30 de 2d 61 8d 6f cc 0a 8a 3f ca 98 98"
        "ec 0b 49 90 48 ce fb f8 b1 65 14 fe fd 00 00 00"
        "00 00 00 00 03 00 01 01 16 fe fd 00 01 00 00 00"
        "00 00 00 00 50 b4 64 b5 c5 c0 71 56 67 00 c2 9b"
        "d6 e4 74 b6 3a 31 0c 93 d8 4e e1 2c 20 66 b6 ce"
        "53 0d 02 6f fa a7 3c 69 73 57 2e f1 9c 30 8c 67"
        "6c 91 38 ee 2e f3 5f b9 d5 38 95 38 c8 0a 31 f9"
        "e1 3b cf 47 d7 be 98 cc fb f5 40 7d f6 bb 40 86"
        "f3 0c 47 08 34",
    },
    {
        from_server,
        "new session ticket, change cipher spec, finished",
        "16 fe fd 00 00 00 00 00 00 00 05 00 c2 04 00 00"
        "b6 00 05 00 00 00 00 00 b6 00 00 1c 20 00 b0 de"
        "9b 91 5c f3 4b 41 77 01 c8 51 9d 14 6e 19 41 69"
        "68 b7 2f 43 52 5e fe a2 eb d9 4d df 89 50 21 0f"
        "99 29 f3 dd 91 db 16 5d fb e2 38 6c fc 9b 47 01"
        "9a 70 aa e4 28 42 46 0b 25 ba 5b 43 46 9b ed 43"
        "47 3e 42 b7 30 1d 5a f4 2f 7c fe d5 9a ea af d9"
        "2c 14 93 30 10 2f cc 36 e8 7c 74 03 1f 05 d4 0d"
        "52 e8 a3 8e 67 78 83 20 18 13 41 48 f8 c5 1e f7"
        "19 32 86 31 61 b7 c1 53 04 f9 e7 c0 25 22 0a 83"
        "7d f4 a8 f8 4f e2 a2 73 86 1f 80 70 c9 2f 0a 25"
        "0a b7 bd 9b 22 06 83 36 25 6a 1f 0f 93 01 eb 99"
        "af 6b 38 0a 2b cd 45 2b 90 7e 34 84 6a be fa 14"
        "fe fd 00 00 00 00 00 00 00 06 00 01 01 16 fe fd"
        "00 01 00 00 00 00 00 00 00 50 ac 08 4a 2f 53 fd"
        "0e 06 2d 47 78 84 de 0d e7 77 d4 bd 2e 73 d1 b2"
        "0a c1 66 2a aa 74 15 ca 0b 07 f0 08 85 ec 47 ef"
        "f4 a8 82 a1 fb ee ea 4a 67 9b 44 b4 7b 47 12 61"
        "0d b1 0a 19 6f ba 7f 52 e8 c9 ef 53 59 ed b4 cf"
        "57 03 12 cf 61 92 cd 0f 9b 1a",
    },
    {
        from_client,
        "application data",
        "17 fe fd 00 01 00 00 00 00 00 01 00 40 bb a3 af"
        "1a 11 7d 47 21 6d 1c b9 99 26 ac 98 a9 97 33 3c"
        "97 25 d2 09 69 b1 38 1e fd 06 01 82 b1 b0 be 3a"
        "21 c2 9d 3f 99 68 00 7e 15 61 31 cd fe 83 fc 3e"
        "fa f5 b3 7b 77 76 37 56 0f b5 2a 60 9a",
    },
    {
        from_client,
        "alert",
        "15 fe fd 00 01 00 00 00 00 00 02 00 40 c1 a0 84"
        "7a 55 42 1f d9 3c 60 27 ab c0 f6 25 9d 7e ee c1"
        "e0 5b b4 1f d8 ca 29 6b f0 ef 18 70 fd 92 02 4e"
        "70 0f 8e ad bf 5a f2 84 4c 8d 3e 87 21 1a ca e5"
        "f0 72 75 f0 af c7 ff 00 1c 17 da 1c ae",
    },
    {
        from_server,
        "alert",
        "15 fe fd 00 01 00 00 00 00 00 01 00 40 05 c7 30"
        "85 a8 64 57 52 91 f5 f3 26 42 6e 43 10 63 06 ed"
        "a2 e0 8b 05 81 23 1c a8 1e 0c 76 69 67 c2 dc 04"
        "9b 88 f7 44 52 ae 3e 9c f0 02 16 3a c8 ed 84 35"
        "97 ec f7 27 03 a8 bd 51 f1 cc 48 60 6c",
    },
};

void test_captured_dtls12() {
    // dtlsserver
    // openssl s_client -connect localhost:9000 -state -debug -dtls1_2

    return_t ret = errorcode_t::success;

    crypto_keychain keychain;
    tls_advisor* advisor = tls_advisor::get_instance();

    {
        _test_case.begin("DTLS dtls12.pcapng");
        tls_session session(session_dtls);
        auto& protection = session.get_tls_protection();

        auto key = session.get_tls_protection().get_keyexchange();
        keychain.load_file(&key, key_certfile, "server.crt", KID_TLS_SERVER_CERTIFICATE_PUBLIC);
        keychain.load_file(&key, key_pemfile, "server.key", KID_TLS_SERVER_CERTIFICATE_PRIVATE);

        constexpr char constexpr_master_secret[] = "93be6304758c8b4f0e106df7bbbb7a4edc23ed6188d44ed4d567b6e375400a74471fda4ad6748c84bda37a19399bd4a4";
        protection.use_pre_master_secret(true);
        protection.set_item(tls_secret_master, base16_decode(constexpr_master_secret));

        play_pcap(&session, capture_dtls12, RTL_NUMBER_OF(capture_dtls12));
    }

    {
        _test_case.begin("DTLS dtls12mtu1500.pcapng");
        tls_session session(session_dtls);
        auto& protection = session.get_tls_protection();

        auto key = session.get_tls_protection().get_keyexchange();
        keychain.load_file(&key, key_certfile, "server.crt", KID_TLS_SERVER_CERTIFICATE_PUBLIC);
        keychain.load_file(&key, key_pemfile, "server.key", KID_TLS_SERVER_CERTIFICATE_PRIVATE);

        constexpr char constexpr_master_secret[] = "cb07e6d5e5abef6d1c36bd39a5433b66f1932d485a40b0aa374c613f1630a91502daeda8f3a9c87007aa2d64c855be24";
        protection.use_pre_master_secret(true);
        protection.set_item(tls_secret_master, base16_decode(constexpr_master_secret));

        play_pcap(&session, capture_dtls12mtu1500, RTL_NUMBER_OF(capture_dtls12mtu1500));
    }
}
