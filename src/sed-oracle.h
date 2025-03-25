#ifndef SED_ORACLE_H
#define SED_ORACLE_H

#include <vector>
#include "except.h"
#include "util.h"
#include "cipher_block.h"
#include <format>
#include <span>
#include <cstdint>
#include <variant>
#include <filesystem>
#include <botan/hex.h>
#include "vector_ct.h"

enum class openpgp_app_e
{
    gnupg,
    rnp
};

#if 0
struct vector_cfb_ciphertext_t
{

    /**
     * The constant value of the leading blocks.
     */
    // std::vector<uint8_t> leading_blocks;
    cipher_block_vec_t<AES_BLOCK_SIZE> leading_blocks;

    /**
     * The number of oracle blocks that can be appended after the leading blocks that will be fully decrypted.
     */
    uint32_t nb_oracle_blocks;

    /**
     * The offset of the decryption result of the oracle blocks into the decryption result.
     */
    uint32_t decryption_result_offset;

    inline std::string to_string_brief() const
    {
        return std::string(
            std::format("leading blocks block count: {}, oracle block capacity: {}, offset into decryption result: {}",
                        leading_blocks.size(),
                        nb_oracle_blocks,
                        decryption_result_offset));
    }
};
#endif

struct cfb_decr_oracle_result_t
{
    std::vector<uint8_t> decryption_result;
    cipher_block_vec_t<AES_BLOCK_SIZE> recovered_encrypted_blocks;
    //vector_cfb_ciphertext_t vector_ciphertext;
    vector_ct_t vector_ciphertext;
};

struct openpgp_app_decr_params_t
{
    openpgp_app_e app_type;
    std::string application_path;
    std::variant<std::monostate, std::string, std::vector<uint8_t>>
        ct_filename_or_data; // monostate means: to be specified during further processing
};

std::vector<uint8_t> invoke_cfb_opgp_decr(openpgp_app_decr_params_t const& decr_params);


std::vector<uint8_t> invoke_cfb_opgp_decr(std::span<const uint8_t> oracle_ciphertext,
                                          openpgp_app_decr_params_t const& decr_params);


std::vector<uint8_t> invoke_cfb_opgp_decr_with_vec_ct(
    std::string const& pgp_msg_log_file_name,
    run_time_ctrl_t ctl,
    // vector_cfb_ciphertext_t const& vec_ct,
    vector_ct_t& vec_ct,
    cipher_block_vec_t<AES_BLOCK_SIZE> const& oracle_ciphertext_blocks,
    std::span<const uint8_t> pkesk_bytes,
    openpgp_app_decr_params_t const& decr_params,
    std::filesystem::path const& msg_file_path);


/**
 * @brief ECB decryption oracle internally using an OpenPGP CFB decryption oracle
 *
 * @param vec_ct vector ciphertext created by an inital query
 * @param oracle_ciphertext_blocks the blocks that shall be ECB encrypted
 * @param pkesk PKESK packet to use for the oracle query
 * @param decr_params decryption parameters
 * @param session_key option (may be empty) session key to verify the ECB encryption result from the oracle
 *
 * @return the ECB encryption result for ECB(oracle_ciphertext_blocks)
 */
cipher_block_vec_t<AES_BLOCK_SIZE> invoke_ecb_opgp_decr(
    std::string const& pgp_msg_log_file_name,
    run_time_ctrl_t ctl,
    vector_ct_t & vec_ct,
    cipher_block_vec_t<AES_BLOCK_SIZE> const& oracle_ciphertext_blocks,
    std::span<const uint8_t> pkesk,
    openpgp_app_decr_params_t const& decr_params,
    std::span<const uint8_t> session_key,
    std::filesystem::path const& msg_file_path

);


cfb_decr_oracle_result_t cfb_opgp_decr_oracle_initial_query(run_time_ctrl_t rtc,
                                                           uint32_t iter,
                                                           openpgp_app_decr_params_t const& decr_params,
                                                           size_t nb_leading_random_bytes,
                                                           std::span<const uint8_t> pkesk,
                                                           std::span<const uint8_t> oracle_blocks_single_pattern,
                                                           uint32_t oracle_pattern_repetitions,
                                                           std::filesystem::path const& msg_file_path,
                                                           std::span<const uint8_t> session_key // may have size 0
);


/**
 * @brief recover the ECB encryption result from the CFB decryption result by means of detecting a repeated pattern of
 * blocks which was set in the ciphertext and thus must be reproduced in the block decryption.
 *
 * @param cfb_decryption_result the result from the CFB decryption returned by the oracle
 * @param nb_blocks_in_single_query_sequence length of the queried sequence in blocks which was placed into the
 * ciphertext repeatedly (at least 2 times)
 * @param nb_leading_random_bytes_len the length of leading purely random bytes in the second-step CFB ciphertext
 * @param second_step_ct the second-step ciphertext that was input into the CFB-decryption oracle (i.e. not featering
 * the 1st-step ciphertext)
 *
 * @return the detected repeated block pattern in the decryption result
 */
std::vector<uint8_t> oracle_blocks_recovery_from_cfb_decryption_result(std::span<uint8_t> cfb_decryption_result,
                                                                       uint32_t nb_blocks_in_single_query_sequence,
                                                                       uint32_t nb_leading_random_bytes_len,
                                                                       std::span<uint8_t> second_step_ct);


cipher_block_vec_t<AES_BLOCK_SIZE> recover_ecb_encryption_for_arbitrary_length_rep_pattern(
    std::span<const uint8_t> cfb_decryption_result,
    uint32_t offset_of_rep_in_decr_res,
    vector_ct_base_t const* query_ct,
    uint32_t ciphertext_block_offset = 0 
    );

#endif /* SED_ORACLE_H */
