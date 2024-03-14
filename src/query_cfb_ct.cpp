
#include "query_cfb_ct.h"
#include <botan/auto_rng.h>


query_cfb_ct_t::query_cfb_ct_t()
{
}

// static
query_cfb_ct_t query_cfb_ct_t::create_from_oracle_blocks(
    std::vector<cipher_block_t<V5AA_CIPH_BLOCK_SIZE>> oracle_block_seq,
    uint32_t nb_oracle_blocks_repetitions,
    uint32_t nb_min_leading_random_bytes)
{

    // std::vector<uint8_t> first_step_ct(block_size + 2);
    query_cfb_ct_t result;

    Botan::AutoSeeded_RNG rng;
    // first step ct is all zero for readability of hex
    //rng.randomize(std::span(result.m_first_step_ct.begin(), result.m_first_step_ct.end()));
    result.m_nb_oracle_blocks_repetitions = nb_oracle_blocks_repetitions;

    size_t nb_leading_random_blocks       = (nb_min_leading_random_bytes + V5AA_CIPH_BLOCK_SIZE - 1) / V5AA_CIPH_BLOCK_SIZE;
    result.m_oracle_blocks_single_pattern = oracle_block_seq;
    result.m_leading_random_blocks.resize(nb_leading_random_blocks);
    for (auto & x : result.m_leading_random_blocks)
    {
        x.randomize(rng);
    }
    /*auto& rob = result.m_oracle_blocks;
    for (uint32_t i = 0; i < nb_oracle_blocks_repetitions; i++)
    {
        rob.insert(rob.end(), oracle_block_seq.begin(), oracle_block_seq.end());
    }*/
    return result;
}
