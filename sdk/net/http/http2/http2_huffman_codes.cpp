/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/http/http2/http_header_compression.hpp>

namespace hotplace {
namespace net {

// RFC 7541 Appendix B. Huffman Code

#define H2HC_ENTRY(s, c) \
    { s, c, }

const huffman_coding::hc_code_t _h2hcodes[] = {
    H2HC_ENTRY(1, "11111111111111111011000"),
    H2HC_ENTRY(2, "1111111111111111111111100010"),
    H2HC_ENTRY(3, "1111111111111111111111100011"),
    H2HC_ENTRY(4, "1111111111111111111111100100"),
    H2HC_ENTRY(5, "1111111111111111111111100101"),
    H2HC_ENTRY(6, "1111111111111111111111100110"),
    H2HC_ENTRY(7, "1111111111111111111111100111"),
    H2HC_ENTRY(8, "1111111111111111111111101000"),
    H2HC_ENTRY(9, "111111111111111111101010"),
    H2HC_ENTRY(10, "111111111111111111111111111100"),
    H2HC_ENTRY(11, "1111111111111111111111101001"),
    H2HC_ENTRY(12, "1111111111111111111111101010"),
    H2HC_ENTRY(13, "111111111111111111111111111101"),
    H2HC_ENTRY(14, "1111111111111111111111101011"),
    H2HC_ENTRY(15, "1111111111111111111111101100"),
    H2HC_ENTRY(16, "1111111111111111111111101101"),
    H2HC_ENTRY(17, "1111111111111111111111101110"),
    H2HC_ENTRY(18, "1111111111111111111111101111"),
    H2HC_ENTRY(19, "1111111111111111111111110000"),
    H2HC_ENTRY(20, "1111111111111111111111110001"),
    H2HC_ENTRY(21, "1111111111111111111111110010"),
    H2HC_ENTRY(22, "111111111111111111111111111110"),
    H2HC_ENTRY(23, "1111111111111111111111110011"),
    H2HC_ENTRY(24, "1111111111111111111111110100"),
    H2HC_ENTRY(25, "1111111111111111111111110101"),
    H2HC_ENTRY(26, "1111111111111111111111110110"),
    H2HC_ENTRY(27, "1111111111111111111111110111"),
    H2HC_ENTRY(28, "1111111111111111111111111000"),
    H2HC_ENTRY(29, "1111111111111111111111111001"),
    H2HC_ENTRY(30, "1111111111111111111111111010"),
    H2HC_ENTRY(31, "1111111111111111111111111011"),
    H2HC_ENTRY(32, "010100"),               // ' '
    H2HC_ENTRY(33, "1111111000"),           // '!'
    H2HC_ENTRY(34, "1111111001"),           // '"'
    H2HC_ENTRY(35, "111111111010"),         // '#'
    H2HC_ENTRY(36, "1111111111001"),        // '$'
    H2HC_ENTRY(37, "010101"),               // '%'
    H2HC_ENTRY(38, "11111000"),             // '&'
    H2HC_ENTRY(39, "11111111010"),          // '''
    H2HC_ENTRY(40, "1111111010"),           // '('
    H2HC_ENTRY(41, "1111111011"),           // ')'
    H2HC_ENTRY(42, "11111001"),             // '*'
    H2HC_ENTRY(43, "11111111011"),          // '+'
    H2HC_ENTRY(44, "11111010"),             // ','
    H2HC_ENTRY(45, "010110"),               // '-'
    H2HC_ENTRY(46, "010111"),               // '.'
    H2HC_ENTRY(47, "011000"),               // '/'
    H2HC_ENTRY(48, "00000"),                // '0'
    H2HC_ENTRY(49, "00001"),                // '1'
    H2HC_ENTRY(50, "00010"),                // '2'
    H2HC_ENTRY(51, "011001"),               // '3'
    H2HC_ENTRY(52, "011010"),               // '4'
    H2HC_ENTRY(53, "011011"),               // '5'
    H2HC_ENTRY(54, "011100"),               // '6'
    H2HC_ENTRY(55, "011101"),               // '7'
    H2HC_ENTRY(56, "011110"),               // '8'
    H2HC_ENTRY(57, "011111"),               // '9'
    H2HC_ENTRY(58, "1011100"),              // ':'
    H2HC_ENTRY(59, "11111011"),             // ';'
    H2HC_ENTRY(60, "111111111111100"),      // '<'
    H2HC_ENTRY(61, "100000"),               // '='
    H2HC_ENTRY(62, "111111111011"),         // '>'
    H2HC_ENTRY(63, "1111111100"),           // '?'
    H2HC_ENTRY(64, "1111111111010"),        // '@'
    H2HC_ENTRY(65, "100001"),               // 'A'
    H2HC_ENTRY(66, "1011101"),              // 'B'
    H2HC_ENTRY(67, "1011110"),              // 'C'
    H2HC_ENTRY(68, "1011111"),              // 'D'
    H2HC_ENTRY(69, "1100000"),              // 'E'
    H2HC_ENTRY(70, "1100001"),              // 'F'
    H2HC_ENTRY(71, "1100010"),              // 'G'
    H2HC_ENTRY(72, "1100011"),              // 'H'
    H2HC_ENTRY(73, "1100100"),              // 'I'
    H2HC_ENTRY(74, "1100101"),              // 'J'
    H2HC_ENTRY(75, "1100110"),              // 'K'
    H2HC_ENTRY(76, "1100111"),              // 'L'
    H2HC_ENTRY(77, "1101000"),              // 'M'
    H2HC_ENTRY(78, "1101001"),              // 'N'
    H2HC_ENTRY(79, "1101010"),              // 'O'
    H2HC_ENTRY(80, "1101011"),              // 'P'
    H2HC_ENTRY(81, "1101100"),              // 'Q'
    H2HC_ENTRY(82, "1101101"),              // 'R'
    H2HC_ENTRY(83, "1101110"),              // 'S'
    H2HC_ENTRY(84, "1101111"),              // 'T'
    H2HC_ENTRY(85, "1110000"),              // 'U'
    H2HC_ENTRY(86, "1110001"),              // 'V'
    H2HC_ENTRY(87, "1110010"),              // 'W'
    H2HC_ENTRY(88, "11111100"),             // 'X'
    H2HC_ENTRY(89, "1110011"),              // 'Y'
    H2HC_ENTRY(90, "11111101"),             // 'Z'
    H2HC_ENTRY(91, "1111111111011"),        // '['
    H2HC_ENTRY(92, "1111111111111110000"),  // '\'
    H2HC_ENTRY(93, "1111111111100"),        // ']'
    H2HC_ENTRY(94, "11111111111100"),       // '^'
    H2HC_ENTRY(95, "100010"),               // '_'
    H2HC_ENTRY(96, "111111111111101"),      // '`'
    H2HC_ENTRY(97, "00011"),                // 'a'
    H2HC_ENTRY(98, "100011"),               // 'b'
    H2HC_ENTRY(99, "00100"),                // 'c'
    H2HC_ENTRY(100, "100100"),              // 'd'
    H2HC_ENTRY(101, "00101"),               // 'e'
    H2HC_ENTRY(102, "100101"),              // 'f'
    H2HC_ENTRY(103, "100110"),              // 'g'
    H2HC_ENTRY(104, "100111"),              // 'h'
    H2HC_ENTRY(105, "00110"),               // 'i'
    H2HC_ENTRY(106, "1110100"),             // 'j'
    H2HC_ENTRY(107, "1110101"),             // 'k'
    H2HC_ENTRY(108, "101000"),              // 'l'
    H2HC_ENTRY(109, "101001"),              // 'm'
    H2HC_ENTRY(110, "101010"),              // 'n'
    H2HC_ENTRY(111, "00111"),               // 'o'
    H2HC_ENTRY(112, "101011"),              // 'p'
    H2HC_ENTRY(113, "1110110"),             // 'q'
    H2HC_ENTRY(114, "101100"),              // 'r'
    H2HC_ENTRY(115, "01000"),               // 's'
    H2HC_ENTRY(116, "01001"),               // 't'
    H2HC_ENTRY(117, "101101"),              // 'u'
    H2HC_ENTRY(118, "1110111"),             // 'v'
    H2HC_ENTRY(119, "1111000"),             // 'w'
    H2HC_ENTRY(120, "1111001"),             // 'x'
    H2HC_ENTRY(121, "1111010"),             // 'y'
    H2HC_ENTRY(122, "1111011"),             // 'z'
    H2HC_ENTRY(123, "111111111111110"),     // '{'
    H2HC_ENTRY(124, "11111111100"),         // '|'
    H2HC_ENTRY(125, "11111111111101"),      // '}'
    H2HC_ENTRY(126, "1111111111101"),       // '~'
    H2HC_ENTRY(127, "1111111111111111111111111100"),
    H2HC_ENTRY(128, "11111111111111100110"),
    H2HC_ENTRY(129, "1111111111111111010010"),
    H2HC_ENTRY(130, "11111111111111100111"),
    H2HC_ENTRY(131, "11111111111111101000"),
    H2HC_ENTRY(132, "1111111111111111010011"),
    H2HC_ENTRY(133, "1111111111111111010100"),
    H2HC_ENTRY(134, "1111111111111111010101"),
    H2HC_ENTRY(135, "11111111111111111011001"),
    H2HC_ENTRY(136, "1111111111111111010110"),
    H2HC_ENTRY(137, "11111111111111111011010"),
    H2HC_ENTRY(138, "11111111111111111011011"),
    H2HC_ENTRY(139, "11111111111111111011100"),
    H2HC_ENTRY(140, "11111111111111111011101"),
    H2HC_ENTRY(141, "11111111111111111011110"),
    H2HC_ENTRY(142, "111111111111111111101011"),
    H2HC_ENTRY(143, "11111111111111111011111"),
    H2HC_ENTRY(144, "111111111111111111101100"),
    H2HC_ENTRY(145, "111111111111111111101101"),
    H2HC_ENTRY(146, "1111111111111111010111"),
    H2HC_ENTRY(147, "11111111111111111100000"),
    H2HC_ENTRY(148, "111111111111111111101110"),
    H2HC_ENTRY(149, "11111111111111111100001"),
    H2HC_ENTRY(150, "11111111111111111100010"),
    H2HC_ENTRY(151, "11111111111111111100011"),
    H2HC_ENTRY(152, "11111111111111111100100"),
    H2HC_ENTRY(153, "111111111111111011100"),
    H2HC_ENTRY(154, "1111111111111111011000"),
    H2HC_ENTRY(155, "11111111111111111100101"),
    H2HC_ENTRY(156, "1111111111111111011001"),
    H2HC_ENTRY(157, "11111111111111111100110"),
    H2HC_ENTRY(158, "11111111111111111100111"),
    H2HC_ENTRY(159, "111111111111111111101111"),
    H2HC_ENTRY(160, "1111111111111111011010"),
    H2HC_ENTRY(161, "111111111111111011101"),
    H2HC_ENTRY(162, "11111111111111101001"),
    H2HC_ENTRY(163, "1111111111111111011011"),
    H2HC_ENTRY(164, "1111111111111111011100"),
    H2HC_ENTRY(165, "11111111111111111101000"),
    H2HC_ENTRY(166, "11111111111111111101001"),
    H2HC_ENTRY(167, "111111111111111011110"),
    H2HC_ENTRY(168, "11111111111111111101010"),
    H2HC_ENTRY(169, "1111111111111111011101"),
    H2HC_ENTRY(170, "1111111111111111011110"),
    H2HC_ENTRY(171, "111111111111111111110000"),
    H2HC_ENTRY(172, "111111111111111011111"),
    H2HC_ENTRY(173, "1111111111111111011111"),
    H2HC_ENTRY(174, "11111111111111111101011"),
    H2HC_ENTRY(175, "11111111111111111101100"),
    H2HC_ENTRY(176, "111111111111111100000"),
    H2HC_ENTRY(177, "111111111111111100001"),
    H2HC_ENTRY(178, "1111111111111111100000"),
    H2HC_ENTRY(179, "111111111111111100010"),
    H2HC_ENTRY(180, "11111111111111111101101"),
    H2HC_ENTRY(181, "1111111111111111100001"),
    H2HC_ENTRY(182, "11111111111111111101110"),
    H2HC_ENTRY(183, "11111111111111111101111"),
    H2HC_ENTRY(184, "11111111111111101010"),
    H2HC_ENTRY(185, "1111111111111111100010"),
    H2HC_ENTRY(186, "1111111111111111100011"),
    H2HC_ENTRY(187, "1111111111111111100100"),
    H2HC_ENTRY(188, "11111111111111111110000"),
    H2HC_ENTRY(189, "1111111111111111100101"),
    H2HC_ENTRY(190, "1111111111111111100110"),
    H2HC_ENTRY(191, "11111111111111111110001"),
    H2HC_ENTRY(192, "11111111111111111111100000"),
    H2HC_ENTRY(193, "11111111111111111111100001"),
    H2HC_ENTRY(194, "11111111111111101011"),
    H2HC_ENTRY(195, "1111111111111110001"),
    H2HC_ENTRY(196, "1111111111111111100111"),
    H2HC_ENTRY(197, "11111111111111111110010"),
    H2HC_ENTRY(198, "1111111111111111101000"),
    H2HC_ENTRY(199, "1111111111111111111101100"),
    H2HC_ENTRY(200, "11111111111111111111100010"),
    H2HC_ENTRY(201, "11111111111111111111100011"),
    H2HC_ENTRY(202, "11111111111111111111100100"),
    H2HC_ENTRY(203, "111111111111111111111011110"),
    H2HC_ENTRY(204, "111111111111111111111011111"),
    H2HC_ENTRY(205, "11111111111111111111100101"),
    H2HC_ENTRY(206, "111111111111111111110001"),
    H2HC_ENTRY(207, "1111111111111111111101101"),
    H2HC_ENTRY(208, "1111111111111110010"),
    H2HC_ENTRY(209, "111111111111111100011"),
    H2HC_ENTRY(210, "11111111111111111111100110"),
    H2HC_ENTRY(211, "111111111111111111111100000"),
    H2HC_ENTRY(212, "111111111111111111111100001"),
    H2HC_ENTRY(213, "11111111111111111111100111"),
    H2HC_ENTRY(214, "111111111111111111111100010"),
    H2HC_ENTRY(215, "111111111111111111110010"),
    H2HC_ENTRY(216, "111111111111111100100"),
    H2HC_ENTRY(217, "111111111111111100101"),
    H2HC_ENTRY(218, "11111111111111111111101000"),
    H2HC_ENTRY(219, "11111111111111111111101001"),
    H2HC_ENTRY(220, "1111111111111111111111111101"),
    H2HC_ENTRY(221, "111111111111111111111100011"),
    H2HC_ENTRY(222, "111111111111111111111100100"),
    H2HC_ENTRY(223, "111111111111111111111100101"),
    H2HC_ENTRY(224, "11111111111111101100"),
    H2HC_ENTRY(225, "111111111111111111110011"),
    H2HC_ENTRY(226, "11111111111111101101"),
    H2HC_ENTRY(227, "111111111111111100110"),
    H2HC_ENTRY(228, "1111111111111111101001"),
    H2HC_ENTRY(229, "111111111111111100111"),
    H2HC_ENTRY(230, "111111111111111101000"),
    H2HC_ENTRY(231, "11111111111111111110011"),
    H2HC_ENTRY(232, "1111111111111111101010"),
    H2HC_ENTRY(233, "1111111111111111101011"),
    H2HC_ENTRY(234, "1111111111111111111101110"),
    H2HC_ENTRY(235, "1111111111111111111101111"),
    H2HC_ENTRY(236, "111111111111111111110100"),
    H2HC_ENTRY(237, "111111111111111111110101"),
    H2HC_ENTRY(238, "11111111111111111111101010"),
    H2HC_ENTRY(239, "11111111111111111110100"),
    H2HC_ENTRY(240, "11111111111111111111101011"),
    H2HC_ENTRY(241, "111111111111111111111100110"),
    H2HC_ENTRY(242, "11111111111111111111101100"),
    H2HC_ENTRY(243, "11111111111111111111101101"),
    H2HC_ENTRY(244, "111111111111111111111100111"),
    H2HC_ENTRY(245, "111111111111111111111101000"),
    H2HC_ENTRY(246, "111111111111111111111101001"),
    H2HC_ENTRY(247, "111111111111111111111101010"),
    H2HC_ENTRY(248, "111111111111111111111101011"),
    H2HC_ENTRY(249, "1111111111111111111111111110"),
    H2HC_ENTRY(250, "111111111111111111111101100"),
    H2HC_ENTRY(251, "111111111111111111111101101"),
    H2HC_ENTRY(252, "111111111111111111111101110"),
    H2HC_ENTRY(253, "111111111111111111111101111"),
    H2HC_ENTRY(254, "111111111111111111111110000"),
    H2HC_ENTRY(255, "11111111111111111111101110"),
    // H2HC_ENTRY(256, "111111111111111111111111111111"),  // EOS
    H2HC_ENTRY(0, nullptr),
};

}  // namespace net
}  // namespace hotplace