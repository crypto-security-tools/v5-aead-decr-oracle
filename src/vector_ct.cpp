
#include "vector_ct.h"
#include "query_cfb_ct.h"
#include <vector>
#include "sed-oracle.h"
#include "opgp_cfb_decr_fun_simulation.h"

namespace 
{
    /**
     * Detect the pattern of repeated blocks | D1 | D1 | D2 | D2 | D3 | D3 | ... | D1 | in the ECB-encrypted result
     *
     * @block_seq Input block sequence with (potentially) the pattern | D1 | D1 | D2 | D2 | D3 | D3 |
     * @pattern_length_in_blocks the maximal index i to Di, counted from i=1
     *
     * @return the maximal index i that was decteded
     *
     */
    size_t nb_detected_block_pattern_reps(cipher_block_vec_t<V5AA_CIPH_BLOCK_SIZE> const& block_seq, size_t pattern_length_in_blocks)
    {
        size_t i = 0;
        cipher_block_vec_t<V5AA_CIPH_BLOCK_SIZE> ref_blocks;
        for (; i < block_seq.size(); i+= pattern_length_in_blocks*2)
        {
            if( block_seq.size() - i < i*pattern_length_in_blocks*2)
            {
                // not enough blocks left for another full pattern (with inner block 2-fold block rep)
                return i;
            }
            bool in_first_outer_rep = (i == 0);
            for( size_t in_pattern_idx = 0; in_pattern_idx < pattern_length_in_blocks*2; in_pattern_idx += 2)
            {
                size_t comb_idx = i + in_pattern_idx;
                if(in_first_outer_rep)
                {
                    // save the Dj, (with j=1,2) block
                    ref_blocks.push_back(block_seq[comb_idx]);
                }
                if(block_seq[comb_idx + 1] != ref_blocks[in_pattern_idx/2])
                {
                    // return the number of so far matched patterns:
                   return i/(pattern_length_in_blocks*2); 
                }

            }
        }
        return i/(pattern_length_in_blocks*2);
    }

}

vector_ct_base_t::~vector_ct_base_t()
{
}

/**
 * serialize the oracle blocks Oi, i ∈  [1, n] as O1 | O1 | O2 | O2 | ... | On | On | O1 | O1 | ... | On | On |
 * where the inner repetition count is always 2 and the outer repetition count is
 * this->m_nb_oracle_blocks_repetitions/2
 *
 *
 * @return the serialized ciphertext
 */
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

    uint32_t nb_double_block_pattern_reps = m_nb_oracle_blocks_repetitions/2;
    cipher_block_vec_t<V5AA_CIPH_BLOCK_SIZE> oracle_blocks_encoded;
    for (uint32_t i = 0; i < nb_double_block_pattern_reps; i++)
    {
        for(size_t block_in_pattern_idx = 0; block_in_pattern_idx < m_oracle_blocks_single_pattern.size(); block_in_pattern_idx++)
        {
            oracle_blocks_encoded.push_back(m_oracle_blocks_single_pattern[block_in_pattern_idx]);
            oracle_blocks_encoded.push_back(m_oracle_blocks_single_pattern[block_in_pattern_idx]);
        }
    }
    cipher_block::append_cb_vec_to_uint8_vec(oracle_blocks_encoded, result);
    std::vector<uint8_t> zero_block(V5AA_CIPH_BLOCK_SIZE);
    result.insert(result.end(), zero_block.begin(), zero_block.end());

    return result;
}

cipher_block_vec_t<AES_BLOCK_SIZE> vector_ct_t::recover_ecb_from_cfb_decr(
    std::span<const uint8_t> cfb_decryption_result,
    std::span<const uint8_t> session_key) const
{
    std::cout << std::format("vector_ct_t::recover_ecb_from_cfb_decr(): checking for pattern of size {}\n", this->m_oracle_blocks_single_pattern.size());
    for (uint32_t ct_block_offs = 0; ct_block_offs < this->m_oracle_blocks_single_pattern.size(); ct_block_offs++)
    {
        cipher_block_vec_t<AES_BLOCK_SIZE> result;
        cipher_block_vec_t<AES_BLOCK_SIZE> candidate_raw_ecb = recover_ecb_encryption_for_arbitrary_length_rep_pattern(
            cfb_decryption_result, this->m_offs_of_oracle_blocks_into_decr_result, this, session_key, ct_block_offs);
        std::cout << std::format("vector_ct_t::recover_ecb_from_cfb_decr(): checking block offset = {}\n", ct_block_offs);
        std::cout << std::format("vector_ct_t::recover_ecb_from_cfb_decr(): checking candidate for pattern repetition: {}\n", candidate_raw_ecb.hex());
        size_t pattern_reps = nb_detected_block_pattern_reps(candidate_raw_ecb, this->m_oracle_blocks_single_pattern.size() );
        if(pattern_reps == 0)
        {
            std::cout << "no matching pattern found for this offset" << std::endl;
            continue;
        }
        /* The canditate ECB still has the pattern | O1 | O1 | O2 | O2 | ... .
         * Thus every 2nd element has to be removed
         */
        size_t cnt = 0;
        for(auto const& block : candidate_raw_ecb)
        {
            if(cnt++ % 2 == 0)
            {
                result.push_back(block);
            }
            if(result.size() == m_oracle_blocks_single_pattern.size())
            {
                /* only produce the decryption of the single pattern */
                break;
            }
        }

        if (session_key.size() > 0)
        {
            cipher_block_vec_t<V5AA_CIPH_BLOCK_SIZE> oracle_blocks_rot;
            oracle_blocks_rot.assign(m_oracle_blocks_single_pattern.begin() + ct_block_offs,m_oracle_blocks_single_pattern.end());
            oracle_blocks_rot.insert(oracle_blocks_rot.end(), m_oracle_blocks_single_pattern.begin(), m_oracle_blocks_single_pattern.begin() + ct_block_offs);
            auto actual_ecb_encrypted = ecb_encrypt_blocks(std::span(session_key), oracle_blocks_rot);
            //if (actual_ecb_encrypted != ecb_encrypted)
            if ( actual_ecb_encrypted != result)
            {
                std::cout << std::format("actual_ecb_encrypted = {}\n", actual_ecb_encrypted.hex());
                std::cout << std::format("result               = {}\n", result.hex());
                std::cerr << "  verification of ECB block encryption for single pattern with actual session key failed\n";
                std::cout << std::format("vector_ct_t::recover_ecb_from_cfb_decr returning empty result\n");
                return cipher_block_vec_t<V5AA_CIPH_BLOCK_SIZE>();
            }
            else
            {
                std::cout << "  verification of ECB block encryption for single pattern with actual session key succeeded\n";
                std::cout << std::format("vector_ct_t::recover_ecb_from_cfb_decr returning result = {}\n",
                                         result.hex());

            }
        }
        return result;
    }
    std::cout << std::format("vector_ct_t::recover_ecb_from_cfb_decr returning empty result\n");
    return cipher_block_vec_t<V5AA_CIPH_BLOCK_SIZE>();
}

// static
vector_ct_t vector_ct_t::create_from_query_cfb_ct(query_cfb_ct_t const *query_ct , uint32_t offs_of_oracle_blocks_into_decr_result, uint32_t oracle_blocks_capacity)
{
    vector_ct_t result(query_ct->leading_blocks(), cipher_block_vec_t<V5AA_CIPH_BLOCK_SIZE>(), query_ct->nb_oracle_blocks_repetitions());
    result.m_offs_of_oracle_blocks_into_decr_result = offs_of_oracle_blocks_into_decr_result;
    result.m_oracle_blocks_capacity = oracle_blocks_capacity;

    return result;
    
}
