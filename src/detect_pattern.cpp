
#include "detect_pattern.h"
#include <format>
#include <iostream>
#include <botan/hex.h>

namespace detect_pattern {

    namespace {

/**
 * @brief Searches for the occurrence of sougth_block in at the beginning of cfb_plaintext and at all possible offsets
 * that are of multiples of pattern_length_in_blocks.
 *
 * @param cfb_plaintext the CFB ciphertext to search
 * @param pattern_length_in_blocks the length of the pattern of repeated blocks expected in the plaintext
 * @param sought_block the block to match within the CFB plaintext 
 *
 * @return
 */
rep_dect_result_t find_block(std::span<const uint8_t> cfb_plaintext, uint32_t const offset,
                uint32_t pattern_length_in_blocks,
                std::span<const uint8_t> sought_block)
{
    const unsigned block_size = 16;
    const uint32_t pattern_length_in_bytes = block_size * pattern_length_in_blocks;

    for (uint32_t i = offset + pattern_length_in_bytes; i + pattern_length_in_bytes < cfb_plaintext.size(); i = i + pattern_length_in_bytes)
    {
        std::span<const uint8_t> candidate_for_match(&cfb_plaintext[i], &cfb_plaintext[i + pattern_length_in_bytes]);
        //std::cout << std::format("    checking for sought_block at offset = {}, ", i);
        //std::cout << std::format("checking match candidate block = {}\n", Botan::hex_encode(candidate_for_match)); 
        if (std::equal(
                candidate_for_match.begin(), candidate_for_match.end(), sought_block.begin(), sought_block.end()))
        {
            std::cout << std::format("found sought block {} at offset {} again at offset {}\n", Botan::hex_encode(sought_block), offset, i);
            return rep_dect_result_t::create_as_true(offset);
        }
    }
    return rep_dect_result_t::create_as_false();
}


}

rep_dect_result_t has_byte_string_repeated_block_at_any_offset(std::span<const uint8_t> cfb_plaintext,
                                                  uint32_t pattern_length_in_blocks)
{

    // approach: since we are looking for repeated blocks while not knowing the offset of the block boundary, we iterate
    // through all possible byte offsets
    const unsigned block_size = 16;
    const uint32_t pattern_length_in_bytes = block_size * pattern_length_in_blocks;
    if (cfb_plaintext.size() < 2 * block_size)
    {
        return rep_dect_result_t::create_as_false();
    }
    for (unsigned offset = 0; offset < cfb_plaintext.size() - 2 * block_size; offset++)
    {
        
        std::span<const uint8_t> sought_block(&cfb_plaintext[offset], &cfb_plaintext[offset + pattern_length_in_bytes]);

        if(rep_dect_result_t res = find_block(cfb_plaintext, offset, pattern_length_in_blocks, sought_block))
        {
            return res;
        }

        //std::cout << std::format("checking intra-block offset = {}\n", offset);
        // iterate through all the possible starting blocks
        /*if(rep_dect_result_t res = has_byte_string_repeated_block_at_certain_offset(cfb_plaintext, pattern_length_in_blocks, offset))
        {
            return res;
        }*/
    }
    return rep_dect_result_t::create_as_false();
}

#if 0
rep_dect_result_t has_byte_string_repeated_block_at_certain_offset(std::span<const uint8_t> cfb_plaintext,
                                                      uint32_t pattern_length_in_blocks,
                                                      uint32_t offset)
{
    const unsigned block_size              = 16;
    const uint32_t pattern_length_in_bytes = block_size * pattern_length_in_blocks;
    // iterate through all the possible block offsets to determine a candidate for the first block of the potential pair
    for (uint32_t i = offset; i + pattern_length_in_bytes + block_size < cfb_plaintext.size(); i = i + block_size)
    {
        std::span<const uint8_t> sought_block(&cfb_plaintext[i], &cfb_plaintext[i + block_size]);
        //std::cout << std::format("  checking offset = {}, ", i);
        //std::cout << std::format("  sought_block of length {} = {}\n", sought_block.size(), Botan::hex_encode(sought_block));
        //std::span<const uint8_t> rem_cfb_plaintext(cfb_plaintext.begin() + i + pattern_length_in_bytes, cfb_plaintext.end());
        // look for block repeated again at a distance of pattern_length_in_blocks
        if(rep_dect_result_t res = find_block(cfb_plaintext, i + pattern_length_in_bytes, pattern_length_in_blocks, sought_block))
        {
            return res;
        }
    }
    return rep_dect_result_t::create_as_false();
}
#endif
}
