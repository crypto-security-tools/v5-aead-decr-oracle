#ifndef _VECTOR_CT_H
#define _VECTOR_CT_H


#include <optional>
#include <span>
#include <vector>
#include <array>
#include <cstdint>
#include <format>
#include "botan/hex.h"
#include "cipher_block.h"

#define V5AA_CIPH_BLOCK_SIZE AES_BLOCK_SIZE

class vector_ct_base_t
{

  public:
    cipher_block_vec_t<V5AA_CIPH_BLOCK_SIZE> const& oracle_blocks_single_pattern() const
    {
        return m_oracle_blocks_single_pattern;
    }

    /**
     * Return the 2-way inner expanded oracle pattern
     *
     * @return | O1 | O1 | O2 | O2 | ... | On | On | for the oracle pattern O1 | O2 | ... | On |
     */
    cipher_block_vec_t<V5AA_CIPH_BLOCK_SIZE> oracle_blocks_single_pattern_expanded() const;

    /**
     * Return the 2-way inner expanded oracle pattern
     *
     * @return | O1 | O1 | O2 | O2 | ... | O1 | O1 | ... | On | On | for the oracle pattern O1 | O2 | ... | On | On |
     */
    cipher_block_vec_t<V5AA_CIPH_BLOCK_SIZE> oracle_blocks_pattern_expanded_and_repeated() const;

    cipher_block_vec_t<V5AA_CIPH_BLOCK_SIZE> const& leading_blocks() const
    {
        return m_leading_random_blocks;
    }

    uint32_t nb_oracle_blocks_repetitions() const
    {
        return m_nb_oracle_blocks_repetitions;
    }

    inline uint32_t oracle_single_pattern_block_count() const
    {
        return static_cast<uint32_t>(m_oracle_blocks_single_pattern.size());
    }

    inline std::string to_string_brief() const
    {
        return std::string(std::format("leading random blocks block count: {},\noracle blocks single pattern: "
                                       "{},\n#oracle pattern repetitions: {}",
                                       m_leading_random_blocks.size(),
                                       Botan::hex_encode(std::span(m_first_step_ct.begin(), m_first_step_ct.end())),
                                       m_oracle_blocks_single_pattern.hex(),
                                       m_nb_oracle_blocks_repetitions));
    }

    /**
     * serialize the oracle blocks Oi, i ∈  [1, n] as O1 | O1 | O2 | O2 | ... | On | On | O1 | O1 | ... | On | On |
     * where the inner repetition count is always 2 and the outer repetition count is
     * this->m_nb_oracle_blocks_repetitions/2
     *
     *
     * @return the serialized ciphertext
     */
    virtual std::vector<uint8_t> serialize() const;


    virtual ~vector_ct_base_t();

  protected:
    inline vector_ct_base_t()
    {
    }

    inline vector_ct_base_t(cipher_block_vec_t<V5AA_CIPH_BLOCK_SIZE> leading_random_blocks,
                            cipher_block_vec_t<V5AA_CIPH_BLOCK_SIZE> oracle_blocks_single_pattern,
                            uint32_t nb_oracle_blocks_repetitions)
        : m_leading_random_blocks(leading_random_blocks), m_oracle_blocks_single_pattern(oracle_blocks_single_pattern),
          m_nb_oracle_blocks_repetitions(nb_oracle_blocks_repetitions)
    {
    }

    std::array<uint8_t, V5AA_CIPH_BLOCK_SIZE + 2> m_first_step_ct = {0};

    cipher_block_vec_t<V5AA_CIPH_BLOCK_SIZE> m_leading_random_blocks;
    cipher_block_vec_t<V5AA_CIPH_BLOCK_SIZE> m_oracle_blocks_single_pattern;

    uint32_t m_nb_oracle_blocks_repetitions;
};

class query_cfb_ct_t;

class vector_ct_t : public vector_ct_base_t
{

  public:
    /**
     * Create with empty oracle blocks
     */
    static vector_ct_t create_from_query_cfb_ct(query_cfb_ct_t const*,
                                                uint32_t offs_of_oracle_blocks_into_decr_result,
                                                uint32_t oracle_blocks_capacity);
    inline uint32_t oracle_blocks_capacity() const
    {
        return m_oracle_blocks_capacity;
    }

    inline void set_oracle_pattern(cipher_block_vec_t<V5AA_CIPH_BLOCK_SIZE> const& oracle_blocks_single_pattern)
    {
        if(this->m_oracle_blocks_capacity < oracle_blocks_single_pattern.size())
        {
           throw Exception("trying to set more oracle blocks than fitting into this vector_ct_t");
        }
        this->m_oracle_blocks_single_pattern = oracle_blocks_single_pattern;
        this->m_nb_oracle_blocks_repetitions = m_oracle_blocks_capacity / oracle_blocks_single_pattern.size();
    }

    inline uint32_t offs_of_oracle_blocks_into_decr_result() const
    {
        return this->m_offs_of_oracle_blocks_into_decr_result;
    }

    cipher_block_vec_t<AES_BLOCK_SIZE> recover_ecb_from_cfb_decr(std::span<const uint8_t> cfb_decryption_result,
                                                                 std::span<const uint8_t> session_key) const;

  private:

    inline vector_ct_t(cipher_block_vec_t<V5AA_CIPH_BLOCK_SIZE> leading_random_blocks,
                            cipher_block_vec_t<V5AA_CIPH_BLOCK_SIZE> oracle_blocks_single_pattern,
                            uint32_t nb_oracle_blocks_repetitions)
        :vector_ct_base_t(leading_random_blocks, oracle_blocks_single_pattern, nb_oracle_blocks_repetitions)
    {
    }


    vector_ct_t();
    uint32_t m_offs_of_oracle_blocks_into_decr_result ;
    uint32_t m_oracle_blocks_capacity;
};

#endif /* _VECTOR_CT_H */
