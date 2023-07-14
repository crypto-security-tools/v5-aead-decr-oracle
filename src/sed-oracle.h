#ifndef SED_ORACLE_H
#define SED_ORACLE_H

#include <vector>
#include "except.h"
#include "util.h"
#include <format>
#include <span>
#include <cstdint>
#include <variant>
#include <filesystem>

enum class openpgp_app_e
{
    gnupg,
    rnp
};

struct cfb_decr_oracle_result_t
{
    std::vector<uint8_t> decryption_result;
    std::vector<uint8_t> recovered_encrypted_blocks;
};

struct openpgp_app_decr_params_t
{
    openpgp_app_e app_type;
    std::string application_path;
    std::variant<std::monostate, std::string, std::vector<uint8_t>>
        ct_filename_or_data; // monostate means: to be specified during further processing
};

std::vector<uint8_t> invoke_cfb_opgp_decr(openpgp_app_decr_params_t const& decr_params);


cfb_decr_oracle_result_t cfb_opgp_decr_oracle(run_time_ctrl_t rtc,
                                              uint32_t iter,
                                              openpgp_app_decr_params_t const& decr_params,
                                              size_t nb_leading_random_bytes,
                                              std::span<const uint8_t> pkesk,
                                              std::span<const uint8_t> oracle_blocks,
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
 * @return
 */
std::vector<uint8_t> oracle_blocks_recovery_from_cfb_decryption_result(std::span<uint8_t> cfb_decryption_result,
                                                                       uint32_t nb_blocks_in_single_query_sequence,
                                                                       uint32_t nb_leading_random_bytes_len,
                                                                       std::span<uint8_t> second_step_ct);

#endif /* SED_ORACLE_H */
