
#include "opgp_cfb_decr_fun_simulation.h"
#include "bit_string.h"
#include "except.h"
#include <span>


#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/hex.h>
#include <botan/rng.h>
#include <iostream>

using namespace Botan;
/**
 * AES CFB decryption
 */
std::vector<uint8_t> openpgp_cfb_decryption_sim (std::span<uint8_t> const& ciphertext, std::optional<std::span<uint8_t>> const& key_opt)
{
    const unsigned block_size = 16;
    std::string cipher_spec("AES-128/CFB");
    if(!key_opt.has_value())
    {
        throw ::Exception("key not set for function openpgp_cfb_decryption()");
    }
    auto key_span = key_opt.value();
    std::vector<uint8_t> key(key_span.begin(), key_span.end());
    std::vector<uint8_t> zero_iv(block_size);
    std::vector<uint8_t> first_ct(&ciphertext[0], &ciphertext[block_size + 2]);
    first_ct.resize(block_size + 2);
    std::vector<uint8_t> second_ct(&ciphertext[block_size + 2], &ciphertext[ciphertext.size() - 1]);
    auto dec = Botan::Cipher_Mode::create(cipher_spec, Botan::Cipher_Dir::Decryption);
    dec->set_key(key);
    dec->start(zero_iv);
    std::cout << "decrypting ciphertext 1 of 2..." << std::endl;
    dec->finish(first_ct);

    std::vector<uint8_t> iv_for_2nd_ct(&first_ct[2], &first_ct[2+block_size]);
    dec->set_key(key);
    dec->start(iv_for_2nd_ct);
    std::cout << "decrypting ciphertext 2 of 2..." << std::endl;
    dec->finish(second_ct);
    return second_ct;

}
