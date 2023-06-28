#ifndef _OPGP_CFB_DECR_FUN_H
#define _OPGP_CFB_DECR_FUN_H

#include <functional>
#include "bit_string.h"

typedef std::function<bit_string_t (bit_string_t const& ciphertext, bit_string_t const& key)> openpgp_cfb_decr_f;


#endif /* _OPGP_CFB_DECR_FUN_H */
