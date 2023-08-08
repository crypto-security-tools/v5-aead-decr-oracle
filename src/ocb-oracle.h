#ifndef _OCB_ORACLE_H
#define _OCB_ORACLE_H

#include "cipher_block.h"
#include "sed-oracle.h"
#include "aead_packet.h"


std::vector<uint8_t> determine_add_data_for_chunk(aead_packet_t const& aead, uint64_t chunk_idx, bool is_final_empty_chunk = false, uint64_t total_bytes = 0);

/**
 * @brief Attack to exchange the order of the first two AEAD chunks of an OCB AEAD packet. By conducting oracle queries, the necessary block decryptions are retrieved. The new AEAD packet is written
 *
 * @param iter the number of the current iteration for purposes of including it in the generated files and the console output
 * @param vec_ct vector ciphertext determined in the previous step
 * @param pkesk the PKESK to prepend to the generated AEAD packet
 * @param app_aparam application parameters for the oracle application invocation
 * @param session_key if non-empty, this value will be used to verify the decryption result returned by the oracle. The verification result is shown in the output.
 * @param aead_packet the packet (including the packet header) of the AEAD packet to be attacked
 */
void ocb_attack_change_order_of_chunks(uint32_t iter, vector_cfb_ciphertext_t const& vec_ct, std::span<const uint8_t> pkesk, openpgp_app_decr_params_t app_aparam, std::span<const uint8_t> session_key, std::span<uint8_t> aead_packet);

#endif /* _OCB_ORACLE_H */
