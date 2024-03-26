
#include "self-test.h"
#include "opgp_cfb_decr_fun_simulation.h"
#include "test_detect_pattern.h"
#include "file_util.h"
#include "generic_packet.h"
#include "ocb-oracle.h"
#include <array>
#include <format>
#include <botan/hex.h>

namespace
{

std::vector<uint8_t> try_open_file_from_top_dir_or_subdir(std::string const& relative_filename)
{
    std::vector<uint8_t> result;
    std::array<const std::string, 2> paths = {relative_filename, "../" + relative_filename};
    for (auto const& path : paths)
    {
        try
        {
            return read_binary_file(path);
        }
        catch (file_exception_t const& e)
        {
        }
    }
    throw file_exception_t(std::format("could not access file either at {} or {}", paths[0], paths[1]));
}

void test_simulated_cfb_decryption()
{
    // test with non-block aligned ciphertext
    std::vector<uint8_t> ct(49);
    std::vector<uint8_t> key(16); // AES 128 for now
    auto pt = openpgp_cfb_decryption_sim(std::span(ct), std::make_optional(std::span(key)));
}

void test_aead_packet()
{
    std::vector<uint8_t> orig_bin = try_open_file_from_top_dir_or_subdir(
        "artifacts/doc.aead.ocb.small-chunks.8B521CB947276EEE8AC09EDD1A3B60A29A18ECAB9E5C48D40F1508914D3EC149.gpg.bin");
    packet_sequence_t seq = parse_packet_sequence(orig_bin);

    // test encoding / decoding:
    auto orig_reencoded = seq.get_encoded();
    if (orig_bin != orig_reencoded)
    {
        std::cout << "orig      = " << Botan::hex_encode(orig_bin) << std::endl;
        std::cout << "reencoded = " << Botan::hex_encode(orig_reencoded) << std::endl;
        throw test_exception_t("reencoded packet sequence differs");
    }
    if (seq.size() != 2)
    {
        throw test_exception_t("packet sequence should have PKESK and AEAD packet");
    }

    aead_packet_t& aead = *dynamic_cast<aead_packet_t*>(seq[1].get());

    std::cout << "dumping packet:\n" << aead.to_string() << std::endl;
    if (aead.aead_chunks().size() < 2)
    {
        throw test_exception_t("chunk count to small for this test");
    }
    // test chunk parsing
    for (auto const& chunk : aead.aead_chunks())
    {
        if (chunk.encrypted.size() == 0)
        {
            throw test_exception_t("chunk has no ciphertext");
        }
        if (chunk.auth_tag.size() != 16)
        {
            throw test_exception_t("chunk has auth_tag with invalid length");
        }
    }
    if(aead.final_auth_tag().size() != 16)
    {
            throw test_exception_t("chunk has final auth tag with invalid length");
    } 

    // test add data
    auto first_add_data_len = determine_add_data_for_chunk(aead, 0).size();
    if (first_add_data_len != 13)
    {
        throw test_exception_t(
            std::format("invalid add. data length for non-final chunk: {} instead of 13", first_add_data_len));
    }
    auto last_add_data_len = determine_add_data_for_chunk(aead, 0, true ).size();
    if (last_add_data_len != 21)
    {
        throw test_exception_t(
            std::format("invalid add. data length for final chunk: {} instead of 21", last_add_data_len));
    }


    std::cout << "test_aead_packet() passed\n";
}

} // namespace

int run_self_tests()
{
    test_simulated_cfb_decryption();
    if (!test_detect_pattern())
    {
        return 1;
    }
    try
    {
        test_aead_packet();
    }
    catch (test_exception_t const& e)
    {
        std::cerr << std::format("test failure: {}\n", e.what());
        return 1;
    }
    catch (Exception const& e)
    {
        std::cerr << std::format("internal error: {}\n", e.what());
        return 1;
    }
    std::cout << "tests passed without error" << std::endl;
    return 0;
}
