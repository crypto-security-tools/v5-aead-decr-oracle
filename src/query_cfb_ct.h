#ifndef _QUERY_CFB_CT_H
#define _QUERY_CFB_CT_H

#include <span>
#include <vector>
#include <cstdint>
#include <format>
#include "cipher_block.h"
#include <iostream>


template <uint8_t BLOCK_SIZE> class query_cfb_ct_t
{
  public:
    static query_cfb_ct_t<BLOCK_SIZE> create_from_oracle_blocks(
        std::vector<cipher_block_t<BLOCK_SIZE>> oracle_block_seq,
        uint32_t nb_oracle_blocks_repetitions,
        uint32_t nb_min_leading_random_bytes);

    std::vector<uint8_t> serialize() const;

    uint32_t offset_of_first_oracle_block() const
    {
        return BLOCK_SIZE + 2 + m_leading_random_blocks.byte_length();
    }

   cipher_block_vec_t<BLOCK_SIZE> const& oracle_blocks_single_pattern() const
   {
     return m_oracle_blocks_single_pattern;
   }
   cipher_block_vec_t<BLOCK_SIZE> const& leading_random_blocks() const
   {
       return m_leading_random_blocks;
   }

    inline uint32_t oracle_single_pattern_block_count() const
    {
        return m_oracle_blocks_single_pattern.size();
    }


  private:
    query_cfb_ct_t();
    std::vector<uint8_t> m_first_step_ct;
    cipher_block_vec_t<BLOCK_SIZE> m_oracle_blocks;
    cipher_block_vec_t<BLOCK_SIZE>  m_oracle_blocks_single_pattern;
    //std::vector<cipher_block_t<BLOCK_SIZE>> m_oracle_blocks_single_pattern;
    cipher_block_vec_t<BLOCK_SIZE> m_leading_random_blocks;
};

// =========== member functions =================


template <uint8_t BLOCK_SIZE> std::vector<uint8_t> query_cfb_ct_t<BLOCK_SIZE>::serialize() const
{

    std::vector<uint8_t> result = m_first_step_ct;
    //std::cout << std::format("serialize: 1st-step-ct: {}\n", Botan::hex_encode(result));
    cipher_block::append_cb_vec_to_uint8_vec(m_leading_random_blocks, result);
    //std::cout << std::format("serialize: + leading random: {}\n", Botan::hex_encode(result));
    cipher_block::append_cb_vec_to_uint8_vec(m_oracle_blocks, result);
    //std::cout << std::format("serialize: + oracle blocks: {}\n", Botan::hex_encode(result));
    return result;
}

template <uint8_t BLOCK_SIZE> query_cfb_ct_t<BLOCK_SIZE>::query_cfb_ct_t()
{
}

// static
template <uint8_t BLOCK_SIZE>
query_cfb_ct_t<BLOCK_SIZE> query_cfb_ct_t<BLOCK_SIZE>::create_from_oracle_blocks(
    std::vector<cipher_block_t<BLOCK_SIZE>> oracle_block_seq,
    uint32_t nb_oracle_blocks_repetitions,
    uint32_t nb_min_leading_random_bytes)
{

    // std::vector<uint8_t> first_step_ct(block_size + 2);
    query_cfb_ct_t<BLOCK_SIZE> result;
    result.m_first_step_ct.resize(BLOCK_SIZE + 2);

    Botan::AutoSeeded_RNG rng;
    // first step ct is all zero for readability of hex
    //rng.randomize(std::span(result.m_first_step_ct.begin(), result.m_first_step_ct.end()));


    size_t nb_leading_random_blocks       = (nb_min_leading_random_bytes + BLOCK_SIZE - 1) / BLOCK_SIZE;
    result.m_oracle_blocks_single_pattern = oracle_block_seq;
    result.m_leading_random_blocks.resize(nb_leading_random_blocks);
    for (auto & x : result.m_leading_random_blocks)
    {
        x.randomize(rng);
    }
    auto& rob = result.m_oracle_blocks;
    for (uint32_t i = 0; i < nb_oracle_blocks_repetitions; i++)
    {
        rob.insert(rob.end(), oracle_block_seq.begin(), oracle_block_seq.end());
    }
    return result;
}

#endif /* _QUERY_CFB_CT_H */
