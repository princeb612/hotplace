/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   regex.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_PATTERN_REGEX__
#define __HOTPLACE_SDK_BASE_PATTERN_REGEX__

#include <functional>
#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/nostd/range.hpp>
#include <string>
#include <vector>

namespace hotplace {

//
// std::regex
//

/**
 * @brief   regular expression
 * @param   const std::string& input [in]
 * @param   const std::string& expr [in]
 * @param   size_t& pos [out]
 * @param   std::list<std::string>& tokens [out]
 * @sa      split_url
 */
void regex_token(const std::string& input, const std::string& expr, size_t& pos, std::list<std::string>& tokens);
void regex_token(const char* input, size_t len, const char* expr, size_t& pos, std::list<range_t>& tokens);
/**
 * @param std::list<std::map<size_t, range_t>>& tokens [out] smatch, cmatch role
 */
void regex_tokens(const char* input, size_t len, const char* expr, size_t& pos, std::list<std::map<size_t, range_t>>& tokens);

}  // namespace hotplace

#endif
