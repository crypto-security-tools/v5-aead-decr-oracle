#ifndef SED_ORACLE_H
#define SED_ORACLE_H

#include <vector>
#include "except.h"
#include <format>
#include <span>
#include <cstdint>

enum class openpgp_app_e {gnupg, rnp};

struct openpgp_app_decr_params_t
{
    openpgp_app_e app_type;
    std::string application_path;
    std::string ct_file_path;
};

std::vector<uint8_t> invoke_cfb_opgp_decr(openpgp_app_decr_params_t const& decr_params);

#endif /* SED_ORACLE_H */
