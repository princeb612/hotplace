/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   ascii_tokens.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/io/parser/types.hpp>

namespace hotplace {
namespace io {

struct ascii_token_table_t {
    uint8 code;
    const char* symbol;
    token_t type;
};
static ascii_token_table_t _ascii_token_table[256] = {
    {0x00, "NUL", token_unknown},  {0x01, "SOH", token_unknown}, {0x02, "STX", token_unknown}, {0x03, "ETX", token_unknown},  {0x04, "EOT", token_unknown},
    {0x05, "ENQ", token_unknown},  {0x06, "ACK", token_unknown}, {0x07, "BEL", token_unknown}, {0x08, "BS", token_unknown},   {0x09, "HT", token_unknown},
    {0x0A, "LF", token_newline},   {0x0B, "VT", token_unknown},  {0x0C, "FF", token_unknown},  {0x0D, "CR", token_unknown},   {0x0E, "SO", token_unknown},
    {0x0F, "SI", token_unknown},   {0x10, "DLE", token_unknown}, {0x11, "DC1", token_unknown}, {0x12, "DC2", token_unknown},  {0x13, "DC3", token_unknown},
    {0x14, "DC4", token_unknown},  {0x15, "NAK", token_unknown}, {0x16, "SYN", token_unknown}, {0x17, "ETB", token_unknown},  {0x18, "CAN", token_unknown},
    {0x19, "EM", token_unknown},   {0x1A, "SUB", token_unknown}, {0x1B, "ESC", token_unknown}, {0x1C, "FS", token_unknown},   {0x1D, "GS", token_unknown},
    {0x1E, "RS", token_unknown},   {0x1F, "US", token_unknown},  {0x20, "SP", token_space},    {0x21, "!", token_unknown},    {0x22, "\"", token_dquote},
    {0x23, "#", token_unknown},    {0x24, "$", token_unknown},   {0x25, "%", token_unknown},   {0x26, "&", token_and},        {0x27, "'", token_squote},
    {0x28, "(", token_lparen},     {0x29, ")", token_rparen},    {0x2A, "*", token_multi},     {0x2B, "+", token_plus},       {0x2C, ",", token_comma},
    {0x2D, "-", token_minus},      {0x2E, ".", token_dot},       {0x2F, "/", token_divide},    {0x30, "0", token_number},     {0x31, "1", token_number},
    {0x32, "2", token_number},     {0x33, "3", token_number},    {0x34, "4", token_number},    {0x35, "5", token_number},     {0x36, "6", token_number},
    {0x37, "7", token_number},     {0x38, "8", token_number},    {0x39, "9", token_number},    {0x3A, ":", token_colon},      {0x3B, ";", token_semicolon},
    {0x3C, "<", token_lesser},     {0x3D, "=", token_equal},     {0x3E, ">", token_greater},   {0x3F, "?", token_unknown},    {0x40, "@", token_unknown},
    {0x41, "A", token_alpha},      {0x42, "B", token_alpha},     {0x43, "C", token_alpha},     {0x44, "D", token_alpha},      {0x45, "E", token_alpha},
    {0x46, "F", token_alpha},      {0x47, "G", token_alpha},     {0x48, "H", token_alpha},     {0x49, "I", token_alpha},      {0x4A, "J", token_alpha},
    {0x4B, "K", token_alpha},      {0x4C, "L", token_alpha},     {0x4D, "M", token_alpha},     {0x4E, "N", token_alpha},      {0x4F, "O", token_alpha},
    {0x50, "P", token_alpha},      {0x51, "Q", token_alpha},     {0x52, "R", token_alpha},     {0x53, "S", token_alpha},      {0x54, "T", token_alpha},
    {0x55, "U", token_alpha},      {0x56, "V", token_alpha},     {0x57, "W", token_alpha},     {0x58, "X", token_alpha},      {0x59, "Y", token_alpha},
    {0x5A, "Z", token_alpha},      {0x5B, "[", token_lbracket},  {0x5C, "\\", token_unknown},  {0x5D, "]", token_rbracket},   {0x5E, "^", token_unknown},
    {0x5F, "_", token_unknown},    {0x60, "`", token_unknown},   {0x61, "a", token_alpha},     {0x62, "b", token_alpha},      {0x63, "c", token_alpha},
    {0x64, "d", token_alpha},      {0x65, "e", token_alpha},     {0x66, "f", token_alpha},     {0x67, "g", token_alpha},      {0x68, "h", token_alpha},
    {0x69, "i", token_alpha},      {0x6A, "j", token_alpha},     {0x6B, "k", token_alpha},     {0x6C, "l", token_alpha},      {0x6D, "m", token_alpha},
    {0x6E, "n", token_alpha},      {0x6F, "o", token_alpha},     {0x70, "p", token_alpha},     {0x71, "q", token_alpha},      {0x72, "r", token_alpha},
    {0x73, "s", token_alpha},      {0x74, "t", token_alpha},     {0x75, "u", token_alpha},     {0x76, "v", token_alpha},      {0x77, "w", token_alpha},
    {0x78, "x", token_alpha},      {0x79, "y", token_alpha},     {0x7A, "z", token_alpha},     {0x7B, "{", token_lbrace},     {0x7C, "|", token_or},
    {0x7D, "}", token_rbrace},     {0x7E, "~", token_unknown},   {0x7F, "DEL", token_unknown}, {0x80, "€", token_unknown},    {0x81, "", token_unknown},
    {0x82, "‚", token_unknown},    {0x83, "ƒ", token_unknown},   {0x84, "„", token_unknown},   {0x85, "…", token_unknown},    {0x86, "†", token_unknown},
    {0x87, "‡", token_unknown},    {0x88, "ˆ", token_unknown},   {0x89, "‰", token_unknown},   {0x8A, "Š", token_unknown},    {0x8B, "‹", token_unknown},
    {0x8C, "Œ", token_unknown},    {0x8D, "", token_unknown},    {0x8E, "Ž", token_unknown},   {0x8F, "", token_unknown},     {0x90, "", token_unknown},
    {0x91, "‘", token_unknown},    {0x92, "’", token_unknown},   {0x93, "“", token_unknown},   {0x94, "”", token_unknown},    {0x95, "•", token_unknown},
    {0x96, "–", token_unknown},    {0x97, "—", token_unknown},   {0x98, "˜", token_unknown},   {0x99, "™", token_unknown},    {0x9A, "š", token_unknown},
    {0x9B, "›", token_unknown},    {0x9C, "œ", token_unknown},   {0x9D, "", token_unknown},    {0x9E, "ž", token_unknown},    {0x9F, "Ÿ", token_unknown},
    {0xA0, "NBSP", token_unknown}, {0xA1, "¡", token_unknown},   {0xA2, "¢", token_unknown},   {0xA3, "£", token_unknown},    {0xA4, "¤", token_unknown},
    {0xA5, "¥", token_unknown},    {0xA6, "¦", token_unknown},   {0xA7, "§", token_unknown},   {0xA8, "¨", token_unknown},    {0xA9, "©", token_unknown},
    {0xAA, "ª", token_unknown},    {0xAB, "«", token_unknown},   {0xAC, "¬", token_unknown},   {0xAD, "­SHY", token_unknown}, {0xAE, "®", token_unknown},
    {0xAF, "¯", token_unknown},    {0xB0, "°", token_unknown},   {0xB1, "±", token_unknown},   {0xB2, "²", token_unknown},    {0xB3, "³", token_unknown},
    {0xB4, "´", token_unknown},    {0xB5, "µ", token_unknown},   {0xB6, "¶", token_unknown},   {0xB7, "·", token_unknown},    {0xB8, "¸", token_unknown},
    {0xB9, "¹", token_unknown},    {0xBA, "º", token_unknown},   {0xBB, "»", token_unknown},   {0xBC, "¼", token_unknown},    {0xBD, "½", token_unknown},
    {0xBE, "¾", token_unknown},    {0xBF, "¿", token_unknown},   {0xC0, "À", token_unknown},   {0xC1, "Á", token_unknown},    {0xC2, "Â", token_unknown},
    {0xC3, "Ã", token_unknown},    {0xC4, "Ä", token_unknown},   {0xC5, "Å", token_unknown},   {0xC6, "Æ", token_unknown},    {0xC7, "Ç", token_unknown},
    {0xC8, "È", token_unknown},    {0xC9, "É", token_unknown},   {0xCA, "Ê", token_unknown},   {0xCB, "Ë", token_unknown},    {0xCC, "Ì", token_unknown},
    {0xCD, "Í", token_unknown},    {0xCE, "Î", token_unknown},   {0xCF, "Ï", token_unknown},   {0xD0, "Ð", token_unknown},    {0xD1, "Ñ", token_unknown},
    {0xD2, "Ò", token_unknown},    {0xD3, "Ó", token_unknown},   {0xD4, "Ô", token_unknown},   {0xD5, "Õ", token_unknown},    {0xD6, "Ö", token_unknown},
    {0xD7, "×", token_unknown},    {0xD8, "Ø", token_unknown},   {0xD9, "Ù", token_unknown},   {0xDA, "Ú", token_unknown},    {0xDB, "Û", token_unknown},
    {0xDC, "Ü", token_unknown},    {0xDD, "Ý", token_unknown},   {0xDE, "Þ", token_unknown},   {0xDF, "ß", token_unknown},    {0xE0, "à", token_unknown},
    {0xE1, "á", token_unknown},    {0xE2, "â", token_unknown},   {0xE3, "ã", token_unknown},   {0xE4, "ä", token_unknown},    {0xE5, "å", token_unknown},
    {0xE6, "æ", token_unknown},    {0xE7, "ç", token_unknown},   {0xE8, "è", token_unknown},   {0xE9, "é", token_unknown},    {0xEA, "ê", token_unknown},
    {0xEB, "ë", token_unknown},    {0xEC, "ì", token_unknown},   {0xED, "í", token_unknown},   {0xEE, "î", token_unknown},    {0xEF, "ï", token_unknown},
    {0xF0, "ð", token_unknown},    {0xF1, "ñ", token_unknown},   {0xF2, "ò", token_unknown},   {0xF3, "ó", token_unknown},    {0xF4, "ô", token_unknown},
    {0xF5, "õ", token_unknown},    {0xF6, "ö", token_unknown},   {0xF7, "÷", token_unknown},   {0xF8, "ø", token_unknown},    {0xF9, "ù", token_unknown},
    {0xFA, "ú", token_unknown},    {0xFB, "û", token_unknown},   {0xFC, "ü", token_unknown},   {0xFD, "ý", token_unknown},    {0xFE, "þ", token_unknown},
    {0xFF, "ÿ", token_unknown},
};

token_t ascii2token(byte_t c) { return _ascii_token_table[c].type; }

}  // namespace io
}  // namespace hotplace
