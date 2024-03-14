
#include "vector_ct.h"

vector_ct_base_t::~vector_ct_base_t()
{
}

std::vector<uint8_t> vector_ct_base_t::serialize() const
{

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
    // std::cout << std::format("serialize: + oracle blocks: {}\n", Botan::hex_encode(result));
    return result;
}
