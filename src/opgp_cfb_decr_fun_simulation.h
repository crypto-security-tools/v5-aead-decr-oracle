#ifndef _OPGP_CFB_DECR_FUN_SIMULATION_H
#define _OPGP_CFB_DECR_FUN_SIMULATION_H

#include <optional>
#include <vector>
#include <span>
#include <cstdint>

std::vector<uint8_t> openpgp_cfb_decryption_sim (std::span<const uint8_t> ciphertext, std::optional<std::span<const uint8_t>> key_opt);

#endif /* _OPGP_CFB_DECR_FUN_SIMULATION_H */
