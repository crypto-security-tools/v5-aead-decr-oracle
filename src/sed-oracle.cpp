

#include "sed-oracle.h"
#include "sedp.h"
#include "except.h"
#include "file_util.h"
#include "subprocess.hpp"
#include <memory>
#include <botan/auto_rng.h>
#include <iostream>
#include "util.h"
#include "opgp_cfb_decr_fun_simulation.h"


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
    std::unique_ptr<sp::Popen> p;
    std::vector<char> to_stdin;

    if (std::holds_alternative<std::string>(decr_params.ct_filename_or_data))
    {
        // std::cout << "creating process with file-based decryption..." << std::endl;
        p = std::unique_ptr<sp::Popen>(new sp::Popen(
            {decr_params.application_path, "--decrypt", std::get<std::string>(decr_params.ct_filename_or_data)},
            sp::output {sp::PIPE},
            sp::error {sp::PIPE}));
    }
    else if (std::holds_alternative<std::vector<uint8_t>>(decr_params.ct_filename_or_data))
    {
        //        throw Exception("stdin input to appication not available");
        p = std::unique_ptr<sp::Popen>(
            new sp::Popen({decr_params.application_path, "--decrypt"}, sp::output {sp::PIPE}, sp::error {sp::PIPE}));
        auto ct_data = std::get<std::vector<uint8_t>>(decr_params.ct_filename_or_data);
        for (size_t i = 0; i < ct_data.size(); i++)
        {
            to_stdin.push_back(ct_data[i]);
        }
    }
    else
    {
        throw Exception("internal error: neither file nor data supplied for ciphertext");
    }

    auto stdout_stderr = p->communicate(to_stdin);
    auto obuf          = stdout_stderr.first;
    auto errbuf        = stdout_stderr.second;

    if (obuf.length)
    {

        p = std::unique_ptr<sp::Popen>(new sp::Popen(
            {decr_params.application_path, "--list--packets", std::get<std::string>(decr_params.ct_filename_or_data)},
            sp::output {sp::PIPE},
            sp::error {sp::PIPE}));
        std::cout << "stdout: " << obuf.buf.data() << std::endl;
        std::cerr << "stderr: " << errbuf.buf.data() << std::endl;
    }
    /*std::cout << "stdout: " << obuf.buf.data() << std::endl;
    std::cout << "stdout len: " << obuf.length << std::endl;
    std::cerr << "stderr: " << errbuf.buf.data() << std::endl;
    std::cerr << "stderr len: " << errbuf.length << std::endl;*/
    std::vector<uint8_t> result;
    result.insert(result.begin(), obuf.buf.data(), obuf.buf.data() + obuf.length);
    return result;
}

std::vector<uint8_t> cfb_opgp_decr_oracle(run_time_ctrl_t rtc,
                                          uint32_t iter,
                                          openpgp_app_decr_params_t const& decr_params,
                                          size_t nb_leading_random_bytes,
                                          std::span<uint8_t> pkesk,
                                          std::span<uint8_t> oracle_blocks,
                                          std::filesystem::path const& msg_file_path,
                                          std::span<uint8_t> session_key)
{
    const unsigned block_size = 16;
    if (!std::holds_alternative<std::monostate>(decr_params.ct_filename_or_data))
    {
        throw Exception("ciphertext or filename specified in decryption parameters, this may not be the case here");
    }

    std::vector<uint8_t> ciphertext;
    size_t nb_leading_random_blocks           = (nb_leading_random_bytes + block_size - 1) / block_size;
    size_t nb_leading_random_bytes_rounded_up = nb_leading_random_bytes * block_size;
    ciphertext.resize(nb_leading_random_bytes_rounded_up);
    Botan::AutoSeeded_RNG rng;
    rng.randomize(std::span(ciphertext));
    ciphertext.insert(ciphertext.end(), oracle_blocks.begin(), oracle_blocks.end());
    symm_encr_data_packet_t sed = symm_encr_data_packet_t::create_sedp_from_ciphertext(ciphertext);
    auto encoded_sed            = sed.get_encoded();
    std::vector<uint8_t> pgp_msg;
    pgp_msg.assign(pkesk.begin(), pkesk.end());
    pgp_msg.insert(pgp_msg.end(), encoded_sed.begin(), encoded_sed.end());
    write_binary_file(std::span(pgp_msg), msg_file_path);
    /*if(msg_file_to_write_opt.has_value())
    {
        write_binary_file(std::span(pgp_msg), msg_file_to_write_opt.value());
    }*/
    auto decr_params_copy(decr_params);
    decr_params_copy.ct_filename_or_data = msg_file_path;
    auto decryption_result               = invoke_cfb_opgp_decr(decr_params_copy);
    if (decryption_result.size() > 0)
    {
        rtc.potentially_write_run_time_file(std::format("random_decryption_input-{}", iter), pgp_msg);
        if (session_key.size() > 0)
        {
            auto plaintext = openpgp_cfb_decryption_sim(ciphertext, std::make_optional(std::span(session_key)));
            write_binary_file(std::span(plaintext), std::format("random_decryption_plaintext-{}", iter));
        }
    }
    return decryption_result;
}
