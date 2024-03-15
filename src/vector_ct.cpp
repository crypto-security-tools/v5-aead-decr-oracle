
#include "vector_ct.h"
#include "query_cfb_ct.h"
#include <vector>

vector_ct_base_t::~vector_ct_base_t()
{
}

std::vector<uint8_t> vector_ct_base_t::serialize() const
{

    if(this->m_oracle_blocks_single_pattern.size() == 0)
    {
        throw Exception("invalid state of vector_ct_base_t: trying to serialize with no oracle pattern set");
    }
    std::vector<uint8_t> result;
    result.assign(m_first_step_ct.begin(), m_first_step_ct.end());
    if (result.size() != m_first_step_ct.size())
    {
        throw Exception("assertion failure for first step ct");
    }
    // std::cout << std::format("serialize: 1st-step-ct: {}\n", Botan::hex_encode(result));
    cipher_block::append_cb_vec_to_uint8_vec(m_leading_random_blocks, result);
    // std::cout << std::format("serialize: + leading random: {}\n", Botan::hex_encode(result));

    for (uint32_t i = 0; i < m_nb_oracle_blocks_repetitions; i++)
    {
        cipher_block::append_cb_vec_to_uint8_vec(m_oracle_blocks_single_pattern, result);
    }
    std::vector<uint8_t> zero_block(V5AA_CIPH_BLOCK_SIZE);
    result.insert(result.end(), zero_block.begin(), zero_block.end());
    // std::cout << std::format("serialize: + oracle blocks: {}\n", Botan::hex_encode(result));
    return result;
}


/*vector_ct_t::vector_ct_t()
{

}*/

// static
vector_ct_t vector_ct_t::create_from_query_cfb_ct(query_cfb_ct_t const *query_ct , uint32_t offs_of_oracle_blocks_into_decr_result, uint32_t oracle_blocks_capacity)
{
    vector_ct_t result(query_ct->leading_blocks(), cipher_block_vec_t<V5AA_CIPH_BLOCK_SIZE>(), query_ct->nb_oracle_blocks_repetitions());
    result.m_offs_of_oracle_blocks_into_decr_result = offs_of_oracle_blocks_into_decr_result;
    result.m_oracle_blocks_capacity = oracle_blocks_capacity;

    return result;
    
}
