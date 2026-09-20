/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   aho_corasick.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <hotplace/sdk/base/nostd/range_set.hpp>
#include <hotplace/sdk/base/pattern/aho_corasick.hpp>

namespace hotplace {

return_t find_unmatched_ranges(const std::multimap<hotplace::range_t, size_t>& results, std::vector<hotplace::range_t>& unmatched) {
    return_t ret = errorcode_t::success;

    unmatched.clear();

    if (results.empty()) return errorcode_t::empty;

    size_t start_bound = results.begin()->first.begin;
    size_t end_bound = results.rbegin()->first.end;

    if (start_bound >= end_bound) return errorcode_t::bad_data;

    hotplace::t_range_set<size_t> rs_unmatched;
    rs_unmatched.add(start_bound, end_bound - 1);

    for (const auto& pair : results) {
        const auto& r = pair.first;

        size_t bound_end = std::min(r.end, end_bound) - 1;
        if (r.begin <= bound_end) {
            rs_unmatched.subtract(r.begin, bound_end);
        }
    }

    auto merged_intervals = rs_unmatched.merge();
    unmatched.reserve(merged_intervals.size());

    for (const auto& item : merged_intervals) {
        hotplace::range_t gap_range;
        gap_range.begin = item.begin;
        gap_range.end = item.end + 1;
        unmatched.push_back(gap_range);
    }

    return ret;
}

return_t travel_ranges(trigger_t trigger, const std::multimap<hotplace::range_t, size_t>& results, std::function<bool(matched_t, hotplace::range_t, size_t)> func) {
    return travel_ranges<decltype(func)>(trigger, results, std::move(func));
}

}  // namespace hotplace
