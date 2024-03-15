#ifndef _OCB_ORACLE_H
#define _OCB_ORACLE_H

#include "cipher_block.h"
#include "sed-oracle.h"
#include "aead_packet.h"

 /* @brief Create the nonce for a v5 AEAD chunk.
 *
 * @param aead the AEAD packet to which the chunks belong
 * @param chunk_idx_non_final the index of the non-final chunk. Is unused if the final empty chunk is processed.
 * @param is_final_empty_chunk whether this is the final empty chunk. Defaults to false.
 *
 * @return  the nonce for the specified chunk
 */
std::vector<uint8_t> determine_nonce_for_aead_chunk(aead_packet_t const& aead,
                                                  uint64_t const chunk_idx_non_final,
                                                  bool const is_final_empty_chunk);

/**
 * @brief Create the additional data for a v5 AEAD chunk.
 *
 * @param aead the AEAD packet to which the chunks belong
 * @param chunk_idx_non_final the index of the non-final chunk. Is unused if the final empty chunk is processed.
 * @param is_final_empty_chunk whether this is the final empty chunk. Defaults to false.
 * @param total_bytes total number of encrypted bytes. Only used for the final empty chunk. Defaults to zero.
 *
 * @return  the additional data
 */
std::vector<uint8_t> determine_add_data_for_chunk(aead_packet_t const& aead, uint64_t chunk_idx_non_final, bool is_final_empty_chunk = false, uint64_t total_bytes = 0);

/**
 * @brief Attack to exchange the order of the first two AEAD chunks of an OCB AEAD packet. By conducting oracle queries, the necessary block decryptions are retrieved. The new AEAD packet is written
 *
 * @param iter the number of the current iteration for purposes of including it in the generated files and the console output
 * @param vec_ct vector ciphertext determined in the previous step
 * @param pkesk the PKESK to prepend to the generated AEAD packet
 * @param session_key if non-empty, this value will be used to verify the decryption result returned by the oracle. The verification result is shown in the output.
 * @param aead_packet the AEAD packet to be attacked
 * @param encrypted_zero_block the encryption result for the zero block from the initial query
 */
void ocb_attack_change_order_of_chunks(uint32_t iter,
                                       run_time_ctrl_t ctl,
                                       // vector_cfb_ciphertext_t const& vec_ct,
                                       vector_ct_t& vec_ct,
                                       std::span<const uint8_t> pkesk,
                                       std::span<const uint8_t> session_key,
                                       aead_packet_t const& aead_packet,
                                       std::span<const uint8_t> encrypted_zero_block,
                                       openpgp_app_decr_params_t const& decr_params,
                                       std::filesystem::path const& msg_file_path);

#endif /* _OCB_ORACLE_H */
