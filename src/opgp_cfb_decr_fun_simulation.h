#ifndef _OPGP_CFB_DECR_FUN_SIMULATION_H
#define _OPGP_CFB_DECR_FUN_SIMULATION_H

#include <optional>
#include <vector>
#include <span>
#include <cstdint>
#include "cipher_block.h"

std::vector<uint8_t> openpgp_cfb_decryption_sim (std::span<const uint8_t> ciphertext, std::optional<std::span<const uint8_t>> key_opt);

cipher_block_t<AES_BLOCK_SIZE> ecb_encrypt_block(std::span<const uint8_t> key_span, cipher_block_t<AES_BLOCK_SIZE> const& input);


cipher_block_vec_t<AES_BLOCK_SIZE> ecb_encrypt_blocks(std::span<const uint8_t> key_span, cipher_block_vec_t<AES_BLOCK_SIZE> const& input);

#endif /* _OPGP_CFB_DECR_FUN_SIMULATION_H */
