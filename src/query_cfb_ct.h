#ifndef _QUERY_CFB_CT_H
#define _QUERY_CFB_CT_H

#include <optional>
#include <span>
#include <vector>
#include <cstdint>
#include <format>
#include "cipher_block.h"
#include <iostream>
#include "vector_ct.h"


class query_cfb_ct_t : public vector_ct_base_t
{
  public:
    static query_cfb_ct_t create_from_oracle_blocks(
        std::vector<cipher_block_t<V5AA_CIPH_BLOCK_SIZE>> oracle_block_seq,
        uint32_t nb_oracle_blocks_repetitions,
        uint32_t nb_min_leading_random_bytes);

    inline std::string to_string_brief() const
    {
        return vector_ct_base_t::to_string_brief();
    }

  private:
    query_cfb_ct_t();
};



#endif /* _QUERY_CFB_CT_H */
