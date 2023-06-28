
#include "eax_decr_oracle.h"


eax_decryption_oracle_t::eax_decryption_oracle_t(bit_string_t const& iv, std::size_t chunk_idx, bit_string_t const& target_ciphertext, openpgp_cfb_decr_f decr_fun, std::optional<bit_string_t> key )
    : m_iv(iv),
    m_chunk_idx(chunk_idx),
    m_target_ciphertext(target_ciphertext),
    m_opgp_cfb_decr_fun(decr_fun),
    m_opt_key(key)
{

}
