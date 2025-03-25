
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

    query_cfb_ct_t result;

    Botan::AutoSeeded_RNG rng;
    // first step ct is all zero for readability of hex
    result.m_nb_oracle_blocks_repetitions = nb_oracle_blocks_repetitions;

    size_t nb_leading_random_blocks       = (nb_min_leading_random_bytes + V5AA_CIPH_BLOCK_SIZE - 1) / V5AA_CIPH_BLOCK_SIZE;
    result.m_oracle_blocks_single_pattern = oracle_block_seq;
    result.m_leading_random_blocks.resize(nb_leading_random_blocks);
    for (auto & x : result.m_leading_random_blocks)
    {
        x.randomize(rng);
    }
    return result;
}
