/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/http/http3/qpack.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

/**
 * RFC 9204 3.2.5.  Relative Indexing
 *
 *        +-----+---------------+-------+
 *        | n-1 |      ...      |   d   |  Absolute Index
 *        + - - +---------------+ - - - +
 *        |  0  |      ...      | n-d-1 |  Relative Index
 *        +-----+---------------+-------+
 *        ^                             |
 *        |                             V
 *  Insertion Point               Dropping Point
 *
 *  n = count of entries inserted
 *  d = count of entries dropped
 *
 *  Figure 2: Example Dynamic Table Indexing - Encoder Stream
 *
 *                 Base
 *                  |
 *                  V
 *      +-----+-----+-----+-----+-------+
 *      | n-1 | n-2 | n-3 | ... |   d   |  Absolute Index
 *      +-----+-----+  -  +-----+   -   +
 *                  |  0  | ... | n-d-3 |  Relative Index
 *                  +-----+-----+-------+
 *
 *  n = count of entries inserted
 *  d = count of entries dropped
 *  In this example, Base = n - 2
 *
 *  Figure 3: Example Dynamic Table Indexing - Relative Index in Representation
 */

/**
 * RFC 9204 3.2.6.  Post-Base Indexing
 *
 *                 Base
 *                  |
 *                  V
 *      +-----+-----+-----+-----+-----+
 *      | n-1 | n-2 | n-3 | ... |  d  |  Absolute Index
 *      +-----+-----+-----+-----+-----+
 *      |  1  |  0  |                    Post-Base Index
 *      +-----+-----+
 *
 *  n = count of entries inserted
 *  d = count of entries dropped
 *  In this example, Base = n - 2
 *
 *  Figure 4: Example Dynamic Table Indexing - Post-Base Index in Representation
 */

/**
 * RFC 9204 4.3.2.  Insert with Name Reference
 *
 *    0   1   2   3   4   5   6   7
 *  +---+---+---+---+---+---+---+---+
 *  | 1 | T |    Name Index (6+)    |
 *  +---+---+-----------------------+
 *  | H |     Value Length (7+)     |
 *  +---+---------------------------+
 *  |  Value String (Length bytes)  |
 *  +-------------------------------+
 *
 *  Figure 6: Insert Field Line -- Indexed Name
 */

/**
 * RFC 9204 4.3.3.  Insert with Literal Name
 *
 *    0   1   2   3   4   5   6   7
 *  +---+---+---+---+---+---+---+---+
 *  | 0 | 1 | H | Name Length (5+)  |
 *  +---+---+---+-------------------+
 *  |  Name String (Length bytes)   |
 *  +---+---------------------------+
 *  | H |     Value Length (7+)     |
 *  +---+---------------------------+
 *  |  Value String (Length bytes)  |
 *  +-------------------------------+
 *
 *  Figure 7: Insert Field Line -- New Name
 */

/**
 * RFC 9204 4.3.4.  Duplicate
 *
 *    0   1   2   3   4   5   6   7
 *  +---+---+---+---+---+---+---+---+
 *  | 0 | 0 | 0 |    Index (5+)     |
 *  +---+---+---+-------------------+
 *
 *  Figure 8: Duplicate
 */

/**
 * RFC 9204 4.4.1.  Section Acknowledgment
 *
 *    0   1   2   3   4   5   6   7
 *  +---+---+---+---+---+---+---+---+
 *  | 1 |      Stream ID (7+)       |
 *  +---+---------------------------+
 *
 *  Figure 9: Section Acknowledgment
 */

/**
 * RFC 9204 4.4.2.  Stream Cancellation
 *
 *    0   1   2   3   4   5   6   7
 *  +---+---+---+---+---+---+---+---+
 *  | 0 | 1 |     Stream ID (6+)    |
 *  +---+---+-----------------------+
 *
 *  Figure 10: Stream Cancellation
 */

/**
 * RFC 9204 4.4.3.  Insert Count Increment
 *
 *    0   1   2   3   4   5   6   7
 *  +---+---+---+---+---+---+---+---+
 *  | 0 | 0 |     Increment (6+)    |
 *  +---+---+-----------------------+
 *
 *  Figure 11: Insert Count Increment
 */

/**
 * RFC 9204 4.5.1.  Encoded Field Section Prefix
 *
 *    0   1   2   3   4   5   6   7
 *  +---+---+---+---+---+---+---+---+
 *  |   Required Insert Count (8+)  |
 *  +---+---------------------------+
 *  | S |      Delta Base (7+)      |
 *  +---+---------------------------+
 *  |      Encoded Field Lines    ...
 *  +-------------------------------+
 *
 *  Figure 12: Encoded Field Section
 */

/**
 * RFC 9204 4.5.2.  Indexed Field Line
 *
 *    0   1   2   3   4   5   6   7
 *  +---+---+---+---+---+---+---+---+
 *  | 1 | T |      Index (6+)       |
 *  +---+---+-----------------------+
 *
 *  Figure 13: Indexed Field Line
 */

/**
 * RFC 9204 4.5.3.  Indexed Field Line with Post-Base Index
 *
 *    0   1   2   3   4   5   6   7
 *  +---+---+---+---+---+---+---+---+
 *  | 0 | 0 | 0 | 1 |  Index (4+)   |
 *  +---+---+---+---+---------------+
 *
 *  Figure 14: Indexed Field Line with Post-Base Index
 */

/**
 * RFC 9204 4.5.4.  Literal Field Line with Name Reference
 * RFC 9204 B.1.  Literal Field Line with Name Reference
 *
 *    0   1   2   3   4   5   6   7
 *  +---+---+---+---+---+---+---+---+
 *  | 0 | 1 | N | T |Name Index (4+)|
 *  +---+---+---+---+---------------+
 *  | H |     Value Length (7+)     |
 *  +---+---------------------------+
 *  |  Value String (Length bytes)  |
 *  +-------------------------------+
 *
 *  Figure 15: Literal Field Line with Name Reference
 */

/**
 * RFC 9204 4.5.5.  Literal Field Line with Post-Base Name Reference
 *
 *    0   1   2   3   4   5   6   7
 *  +---+---+---+---+---+---+---+---+
 *  | 0 | 0 | 0 | 0 | N |NameIdx(3+)|
 *  +---+---+---+---+---+-----------+
 *  | H |     Value Length (7+)     |
 *  +---+---------------------------+
 *  |  Value String (Length bytes)  |
 *  +-------------------------------+
 *
 *  Figure 16: Literal Field Line with Post-Base Name Reference
 */

/**
 * RFC 9204 4.5.6.  Literal Field Line with Literal Name
 *
 *    0   1   2   3   4   5   6   7
 *  +---+---+---+---+---+---+---+---+
 *  | 0 | 0 | 1 | N | H |NameLen(3+)|
 *  +---+---+---+---+---+-----------+
 *  |  Name String (Length bytes)   |
 *  +---+---------------------------+
 *  | H |     Value Length (7+)     |
 *  +---+---------------------------+
 *  |  Value String (Length bytes)  |
 *  +-------------------------------+
 *
 *  Figure 17: Literal Field Line with Literal Name
 */

qpack_encoder::qpack_encoder() : http_header_compression() {
    // RFC 9204 Appendix A.  Static Table
    http_resource::get_instance()->for_each_qpack_static_table([&](uint32 index, const char* name, const char* value) -> void {
        _static_table.insert(std::make_pair(name, std::make_pair(value ? value : "", index)));
        _static_table_index.insert(std::make_pair(index, std::make_pair(name, value ? value : "")));
    });
}

qpack_encoder& qpack_encoder::encode_name_reference(hpack_session* session, binary_t& bin, const char* name, const char* value) {
    // studying
    return *this;
}

}  // namespace net
}  // namespace hotplace
