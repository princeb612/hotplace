/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   parser_sdk.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2026-08-29   Soo Han and Gemini  study
 *
 */

#ifndef __HOTPLACE_SDK_IO_PARSER_PARSERSDK__
#define __HOTPLACE_SDK_IO_PARSER_PARSERSDK__

#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/io/parser/types.hpp>
#include <map>
#include <set>
#include <stack>
#include <vector>

namespace hotplace {
namespace io {

void compute_first_and_follow_sets(const cfg_grammar& grammar, parser_temporary_context_t& context);
std::set<LR0_item> closure_lr0(const cfg_grammar& grammar, std::set<LR0_item> items);
void build_lr0_states(const cfg_grammar& grammar, parser_temporary_context_t& context, parser_goto_table_t& goto_table);
bool generate_lalr1_tables(const cfg_grammar& grammar, parser_temporary_context_t& context, const parser_goto_table_t& goto_table,
                           parser_lalr1_action_table_t& action_table);
bool generate_glr_tables(const cfg_grammar& grammar, parser_temporary_context_t& context, const parser_goto_table_t& goto_table, parser_glr_action_table_t& action_table);

}  // namespace io
}  // namespace hotplace

#endif
