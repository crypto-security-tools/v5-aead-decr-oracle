

#include "sed-oracle.h"
#include "subprocess.hpp"

// Note: boost.process seems badly maintained: https://github.com/bitcoin/bitcoin/issues/24907
//
namespace sp = subprocess;

std::vector<uint8_t> invoke_cfb_opgp_decr(openpgp_app_decr_params_t const& decr_params)
{
    using enum openpgp_app_e;
    if (decr_params.app_type != gnupg)
    {
        throw cli_exception_t("cfb_opgp_decr_oracle(): only GnuPG is currently supported as an oracle");
    }

    auto p = sp::Popen({decr_params.application_path, "--decrypt", decr_params.ct_file_path}, sp::output {sp::PIPE}, sp::error {sp::PIPE});
    auto stdout_stderr = p.communicate();
    auto obuf          = stdout_stderr.first;
    auto errbuf        = stdout_stderr.second;
    /*std::cout << "stdout: " << obuf.buf.data() << std::endl;
    std::cout << "stdout len: " << obuf.length << std::endl;
    std::cerr << "stderr: " << errbuf.buf.data() << std::endl;
    std::cerr << "stderr len: " << errbuf.length << std::endl;*/
    std::vector<uint8_t> result;
    result.insert(result.begin(), obuf.buf.data(), obuf.buf.data() + obuf.length);
    return result;
}

std::vector<uint8_t> cfb_opgp_decr_oracle(openpgp_app_decr_params_t const& decr_params, size_t nb_leading_random_blocks)
{
 throw Exception("cfb_opgp_decr_oracle () not implemented");
}

