#ifndef _DETECT_PATTERN_H
#define _DETECT_PATTERN_H

#include <span>
#include <vector>
#include <cstdint>

namespace detect_pattern
{

struct rep_dect_result_t
{
    inline static rep_dect_result_t create_as_false()
    {
        return rep_dect_result_t({.m_nb_rep_blocks = 0, .m_offset = 0});
    }

    inline static rep_dect_result_t create_as_true(uint32_t offset, uint32_t nb_rep_blocks)
    {
        return rep_dect_result_t({.m_nb_rep_blocks= nb_rep_blocks, .m_offset = offset});
    }
    
    inline uint32_t nb_repeated_blocks() const
    {
        return m_nb_rep_blocks;
    }

    inline uint32_t offset() const
    {
        return m_offset;
    }

    explicit operator bool() const
    {
        return m_nb_rep_blocks > 0;
    }


    uint32_t m_nb_rep_blocks;
    uint32_t m_offset;
};

/**
 * @brief Find a block repetition with distance of pattern_length_in_blocks blocks within cfb_ciphertext
 *
 * @param cfb_plaintext The CFB ciphertext within which to find the block repetition.
 * @param pattern_length_in_blocks The length of the repeated pattern that is expected.
 *
 * @return a rep_dect_result_t with have_repetition=true if at least one such repetition occurs in the CFB ciphertext.
 */

rep_dect_result_t has_byte_string_repeated_block_at_any_offset(std::span<const uint8_t> cfb_plaintext,
                                                               uint32_t pattern_length_in_blocks);

} // namespace detect_pattern
#endif /* _DETECT_PATTERN_H */
