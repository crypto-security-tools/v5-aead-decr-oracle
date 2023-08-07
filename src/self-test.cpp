
#include "self-test.h"
#include "opgp_cfb_decr_fun_simulation.h"
#include "test_detect_pattern.h"
#include "file_util.h"
#include <array>
#include <format>

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
    // TODO: NEED PURE AEAD PACKET, NOT THIS ONE WITH PREPENDED PKESK
    std::vector<uint8_t> aead_bin = try_open_file_from_top_dir_or_subdir("artifacts/doc.aead.ocb.small-chunks.8B521CB947276EEE8AC09EDD1A3B60A29A18ECAB9E5C48D40F1508914D3EC149.gpg.bin");


}

}

int run_self_tests()
{
    test_simulated_cfb_decryption();
    if (!test_detect_pattern())
    {
        return 1;
    }
    return 0;
}
