#ifndef _DETECT_PATTERN_H
#define _DETECT_PATTERN_H

#include <span>
#include <vector>
#include <cstdint>

namespace detect_pattern {

/**
 * @brief Find a block repetition with distance of pattern_length_in_blocks blocks within cfb_ciphertext
 *
 * @param cfb_plaintext The CFB ciphertext within which to find the block repetition.
 * @param pattern_length_in_blocks The length of the repeated pattern that is expected.
 *
 * @return true if at least one such repetition occurs in the CFB ciphertext.
 */
bool has_byte_string_repeated_block_at_any_offset(std::span<const uint8_t> cfb_plaintext,
                                                  uint32_t pattern_length_in_blocks);

}
#endif /* _DETECT_PATTERN_H */
