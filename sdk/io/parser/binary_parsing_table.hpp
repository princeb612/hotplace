/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file    binary_parsing_table.hpp
 * @author  Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_IO_PARSER_BINARYPARSINGTABLE__
#define __HOTPLACE_SDK_IO_PARSER_BINARYPARSINGTABLE__

#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/io/parser/types.hpp>

namespace hotplace {
namespace io {

#pragma pack(push, 1)
// struct bpt_header_t {
//     char magic[4];
//     uint16 version;
//     uint16 endian;
//     uint32 crc32;
//     uint64 blocks_size;
// };
//
// struct bpt_string_item_t {
//     uint16 len;
//     const char* symbol;  // not null-terminated
// };
//
// struct bpt_production_item_t {
//     uint32 id;
//     uint32 lhs;
//     uint32 count;
//     uint32* rhs;
// };

struct bpt_action_item_t {
    uint32 state;
    uint32 lookahead;
    uint8 action;
    uint32 target;
};

struct bpt_goto_item_t {
    uint32 state;
    uint32 nonterminal;
    uint32 next_state;
};
#pragma pack(pop)

/**
 * @brief   parsing table
 */
class binary_parsing_table {
   public:
    binary_parsing_table();

    return_t learn(parser_t* parser);
    uint32 lookup(const std::string& symbol);
    std::string rlookup(uint32 index);
    bool ready() const;

    // production table
    return_t buildup_production(const parser_production& item);
    // terminal
    return_t buildup_terminal(const std::string& term);
    // action table
    return_t buildup_action(uint32 state, const std::string& lookahead, const parser_action_state& action);
    // goto table
    return_t buildup_goto(uint32 state, const std::string& nonterm, uint32 next_state);

    // read
    return_t read(const std::string& filename, parser_t& parser);
    // write
    return_t write(const std::string& filename, parser_t& parser);

   protected:
    void clear();

   protected:
    mutable critical_section _lock;
    std::map<std::string, uint32> _string_index;  // lookup, string table
    std::map<uint32, std::string> _reverse_map;   // rlookup
    //
    struct production_t {
        uint32 id;
        uint32 lhs;
        std::vector<uint32> rhs;
    };
    std::vector<production_t> _production_table;
    std::vector<uint32> _terminals;
    std::vector<bpt_action_item_t> _action_table;
    std::vector<bpt_goto_item_t> _goto_table;
};

}  // namespace io
}  // namespace hotplace

#endif
