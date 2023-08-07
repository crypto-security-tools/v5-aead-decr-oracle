
#include "detect_pattern.h"
#include "cipher_block.h"
#include <format>
#include <iostream>
#include <botan/hex.h>

namespace detect_pattern
{

namespace
{

uint32_t count_blocks_in_repeatet_pattern_area(std::span<const uint8_t> sought_pattern,
                                               std::span<const uint8_t> decr_res_from_repeat_pos)
{
    uint32_t block_count = 0;
    if (sought_pattern.size() % AES_BLOCK_SIZE)
    {
        throw Exception("count_blocks_in_repeatet_pattern_area(): sought_pattern is not a multiple of the block size");
    }
    uint32_t sought_pattern_block_size = sought_pattern.size() / AES_BLOCK_SIZE;
    std::cout << std::format("count_blocks_in_repeatet_pattern_area(): sought_pattern_block_size = {}, decryption result part size = {}\n", sought_pattern_block_size, decr_res_from_repeat_pos.size());
    for (uint32_t i = 0; i + sought_pattern.size() <= decr_res_from_repeat_pos.size(); i += sought_pattern.size())
    {
        auto candidate_for_match =
            std::span<const uint8_t>(&decr_res_from_repeat_pos[i], &decr_res_from_repeat_pos[i + sought_pattern.size()]);
        if (std::equal(
                candidate_for_match.begin(), candidate_for_match.end(), sought_pattern.begin(), sought_pattern.end()))
        {
            block_count += sought_pattern_block_size;
            std::cout << std::format("count_blocks_in_repeatet_pattern_area(): counting this match, now {} block (i = {})\n",
                                     block_count, i);
        }
        else
        {
            break;
        }
    }
    return block_count;
}

/**
 * @brief Searches for the occurrence of sougth_block in at offset + pattern_length_in_bytes bytes from the beginning of cfb_plaintext and at all possible offsets
 * that are of multiples of pattern_length_in_blocks.
 *
 * @param cfb_plaintext the CFB ciphertext to search
 * @param pattern_length_in_blocks the length of the pattern of repeated blocks expected in the plaintext
 * @param sought_block the block to match within the CFB plaintext
 *
 * @return
 */
rep_dect_result_t find_block(std::span<const uint8_t> cfb_plaintext,
                             uint32_t const offset,
                             uint32_t pattern_length_in_blocks,
                             std::span<const uint8_t> sought_block)
{
    const unsigned block_size              = AES_BLOCK_SIZE;
    const uint32_t pattern_length_in_bytes = block_size * pattern_length_in_blocks;

    for (uint32_t i = offset + pattern_length_in_bytes; i + pattern_length_in_bytes < cfb_plaintext.size();
         i          = i + pattern_length_in_bytes)
    {
        std::span<const uint8_t> candidate_for_match(&cfb_plaintext[i], &cfb_plaintext[i + pattern_length_in_bytes]);
        // std::cout << std::format("    checking for sought_block at offset = {}, ", i);
        // std::cout << std::format("checking match candidate block = {}\n", Botan::hex_encode(candidate_for_match));
        if (std::equal(
                candidate_for_match.begin(), candidate_for_match.end(), sought_block.begin(), sought_block.end()))
        {
            std::cout << std::format(
                "find_block(): found sought block {} at offset {} again at offset {} (remaining cfb plaintext size = {}) \n", Botan::hex_encode(sought_block), offset, i, cfb_plaintext.size() - i);
            // now count the number of repetitions
            uint32_t nb_rep_blocks = 1 + count_blocks_in_repeatet_pattern_area(
                sought_block, std::span<const uint8_t>(&cfb_plaintext[i], &cfb_plaintext[cfb_plaintext.size()]));
            if(nb_rep_blocks == 0)
            {
                throw Exception("internal error: nb_rep_blocks must be at least 1");
            }
            std::cout << std::format("nb_rep_blocks = {}\n", nb_rep_blocks); 
            return rep_dect_result_t::create_as_true(offset, nb_rep_blocks);
        }
    }
    return rep_dect_result_t::create_as_false();
}


} // namespace

rep_dect_result_t has_byte_string_repeated_block_at_any_offset(std::span<const uint8_t> cfb_plaintext,
                                                               uint32_t pattern_length_in_blocks)
{

    // approach: since we are looking for repeated blocks while not knowing the offset of the block boundary, we iterate
    // through all possible byte offsets
    const unsigned block_size              = AES_BLOCK_SIZE;
    const uint32_t pattern_length_in_bytes = block_size * pattern_length_in_blocks;
    if (cfb_plaintext.size() < 2 * block_size)
    {
        return rep_dect_result_t::create_as_false();
    }
    for (unsigned offset = 0; offset < cfb_plaintext.size() - 2 * block_size; offset++)
    {

        std::span<const uint8_t> sought_block(&cfb_plaintext[offset], &cfb_plaintext[offset + pattern_length_in_bytes]);

        if (rep_dect_result_t res = find_block(cfb_plaintext, offset, pattern_length_in_blocks, sought_block))
        {
            return res;
        }

        // std::cout << std::format("checking intra-block offset = {}\n", offset);
        //  iterate through all the possible starting blocks
        /*if(rep_dect_result_t res = has_byte_string_repeated_block_at_certain_offset(cfb_plaintext,
        pattern_length_in_blocks, offset))
        {
            return res;
        }*/
    }
    return rep_dect_result_t::create_as_false();
}

} // namespace detect_pattern
