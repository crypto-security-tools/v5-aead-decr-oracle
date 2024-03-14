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

    inline uint32_t oracle_single_pattern_block_count() const
    {
        return static_cast<uint32_t>(m_oracle_blocks_single_pattern.size());
    }


    inline std::string to_string_brief() const
    {
        return std::string(
            std::format("leading random blocks block count: {},\noracle blocks single pattern: {},\n#oracle pattern repetitions: {}",
                        m_leading_random_blocks.size(),
                        Botan::hex_encode(std::span(m_first_step_ct.begin(), m_first_step_ct.end())),
                         m_oracle_blocks_single_pattern.hex(),
                        m_nb_oracle_blocks_repetitions 
                        ));
    }


    std::vector<uint8_t> serialize() const;

    virtual ~vector_ct_base_t();

  protected:

    std::array<uint8_t, V5AA_CIPH_BLOCK_SIZE + 2> m_first_step_ct = { 0 };

    cipher_block_vec_t<V5AA_CIPH_BLOCK_SIZE> m_leading_random_blocks;
    cipher_block_vec_t<V5AA_CIPH_BLOCK_SIZE>  m_oracle_blocks_single_pattern;

    uint32_t m_nb_oracle_blocks_repetitions;

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
