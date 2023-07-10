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

enum class openpgp_app_e {gnupg, rnp};

struct openpgp_app_decr_params_t
{
    openpgp_app_e app_type;
    std::string application_path;
    std::variant<std::monostate, std::string, std::vector<uint8_t>> ct_filename_or_data; // monostate means: to be specified during further processing
    
};

std::vector<uint8_t> invoke_cfb_opgp_decr(openpgp_app_decr_params_t const& decr_params);


std::vector<uint8_t> cfb_opgp_decr_oracle(run_time_ctrl_t rtc, uint32_t iter,openpgp_app_decr_params_t const& decr_params,
                                          size_t nb_leading_random_bytes,
                                          std::span<uint8_t> pkesk,
                                          std::span<uint8_t> oracle_blocks,
                                          std::filesystem::path const& msg_file_path,
                                          std::span<uint8_t> session_key // may have size 0
                                          );

#endif /* SED_ORACLE_H */
