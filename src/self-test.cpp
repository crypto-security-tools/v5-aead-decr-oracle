
#include "self-test.h"
#include "opgp_cfb_decr_fun_simulation.h"
#include "test_detect_pattern.h"
#include "file_util.h"
#include "generic_packet.h"
#include <array>
#include <format>
#include <botan/hex.h>

namespace
{

std::vector<uint8_t> try_open_file_from_top_dir_or_subdir(std::string const& relative_filename)
{
    std::vector<uint8_t> result;
    std::array<const std::string, 2> paths = { relative_filename, "../" + relative_filename};
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

void test_aead_packet_decoding_encoding()
{
    std::vector<uint8_t> orig_bin = try_open_file_from_top_dir_or_subdir("artifacts/doc.aead.ocb.small-chunks.8B521CB947276EEE8AC09EDD1A3B60A29A18ECAB9E5C48D40F1508914D3EC149.gpg.bin");
    packet_sequence_t seq = parse_packet_sequence(orig_bin);
   
    auto orig_reencoded = seq.get_encoded();
    if(orig_bin != orig_reencoded)
    {
        std::cout << "orig      = " << Botan::hex_encode(orig_bin) << std::endl;
        std::cout << "reencoded = " << Botan::hex_encode(orig_reencoded) << std::endl;
        throw test_exception_t("reencoded packet sequence differs");
    }
    if(seq.size() != 2)
    {
        throw test_exception_t("packet sequence should have PKESK and AEAD packet");
    }
    std::cout << "test_aead_packet_decoding_encoding() passed\n";
 
        


}

}

int run_self_tests()
{
    test_simulated_cfb_decryption();
    if (!test_detect_pattern())
    {
        return 1;
    }
    try
    {
        test_aead_packet_decoding_encoding();
    }
    catch(test_exception_t const& e)
    {
        std::cerr << std::format("test failure: {}\n", e.what());
        return 1;
    }
    catch(Exception const& e)
    {
        std::cerr << std::format("internal error: {}\n", e.what());
        return 1;
    }
    std::cout << "tests passed without error" << std::endl;
    return 0;
}
