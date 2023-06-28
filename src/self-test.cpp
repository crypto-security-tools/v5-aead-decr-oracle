
#include "self-test.h"
#include "opgp_cfb_decr_fun_simulation.h"


namespace {

    void test_simulated_cfb_decryption()
    {
        // test with non-block aligned ciphertext
        std::vector<uint8_t> ct(49);
        std::vector<uint8_t> key(16); // AES 128 for now
        auto pt = openpgp_cfb_decryption_sim(std::span(ct), std::make_optional(std::span(key)));
    }

}

int run_self_tests()
{
    test_simulated_cfb_decryption();
    return 0;
}
