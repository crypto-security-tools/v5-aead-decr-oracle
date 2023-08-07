#ifndef _EAX_DECR_ORACLE_H
#define _EAX_DECR_ORACLE_H

#include "bit_string.h"
#include "opgp_cfb_decr_fun.h"
#include "cipher_block.h"
#include <optional>

class eax_decryption_oracle_t
{

    public:
        eax_decryption_oracle_t(bit_string_t const& iv, std::size_t chunk_idx, bit_string_t const& target_ciphertext, openpgp_cfb_decr_f decr_fun, std::optional<bit_string_t> key );
    private:
        bit_string_t  m_iv;
        std::size_t m_chunk_idx;
        bit_string_t m_target_ciphertext;
        openpgp_cfb_decr_f m_opgp_cfb_decr_fun;
        std::optional<bit_string_t> m_opt_key;

};

#endif /* _EAX_DECR_ORACLE_H */
