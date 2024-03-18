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

#if 0

    inline bool is_set_nb_decryptable_blocks() const
    {
        return m_opt_nb_decryptable_blocks.has_value();
    }

    inline uint32_t get_nb_decryptable_blocks() const
    {
        if(m_opt_nb_decryptable_blocks.has_value())
        {
            return m_opt_nb_decryptable_blocks.value();
        }
        throw Exception("invalid state of query_cfb_ct_t: m_opt_nb_decryptable_blocks not set when get_nb_decryptable_blocks() was called");
    }

    inline void set_nb_decryptable_blocks(uint32_t n)
    {
        m_opt_nb_decryptable_blocks = n;
    }


    inline bool is_set_decr_res_offs() const
    {
        return m_opt_decr_res_offs.has_value();
    }
   
   /**
    * Get the offset of the decryption result of the oracle blocks within the returned SED plaintext.
    */ 
    inline uint32_t get_decr_res_offs() const
    {
        if(m_opt_decr_res_offs.has_value())
        {
            return m_opt_decr_res_offs.value();
        }
        throw Exception("invalid state of query_cfb_ct_t: m_opt_decr_res_offs not set when get_decr_res_offs() was called");
    }

   /**
    * Set the offset of the decryption result of the oracle blocks within the returned SED plaintext.
    */ 
    inline void set_decr_res_offs(uint32_t n)
    {
        m_opt_decr_res_offs= n;
    }
#endif

#endif /* _VECTOR_CT_H */
