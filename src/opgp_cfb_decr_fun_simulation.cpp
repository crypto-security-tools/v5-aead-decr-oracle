
#include "opgp_cfb_decr_fun_simulation.h"
#include "bit_string.h"
#include "except.h"
#include "util.h"
#include "cipher_block.h"
#include <span>


#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/block_cipher.h>
#include <botan/hex.h>
#include <botan/rng.h>
#include <iostream>

using namespace Botan;
/**
 * AES CFB decryption as specified for OpenPGP (2-step encryption)
 */
std::vector<uint8_t> openpgp_cfb_decryption_sim(std::span<const uint8_t> ciphertext,
                                                std::optional<std::span<const uint8_t>> key_opt)
{
    const unsigned block_size = 16;
    if (!key_opt.has_value())
    {
        throw ::Exception("key not set for function openpgp_cfb_decryption()");
    }
    auto key_span = key_opt.value();

    std::string cipher_spec = botan_aes_cfb_cipher_spec_from_key_byte_len(key_span.size());
    std::vector<uint8_t> key(key_span.begin(), key_span.end());
    std::vector<uint8_t> zero_iv(block_size);
    std::vector<uint8_t> first_ct(&ciphertext[0], &ciphertext[block_size + 2]);
    first_ct.resize(block_size + 2);
    std::vector<uint8_t> second_ct(&ciphertext[block_size + 2], &ciphertext[ciphertext.size() - 1]);
    auto dec = Botan::Cipher_Mode::create(cipher_spec, Botan::Cipher_Dir::Decryption);

    if (dec == nullptr)
    {
        throw ::Exception("failed to set up Botan CFB decryption");
    }
    dec->set_key(key);
    dec->start(zero_iv);
    dec->finish(first_ct);

    std::vector<uint8_t> iv_for_2nd_ct(&first_ct[2], &first_ct[2 + block_size]);
    dec->set_key(key);
    dec->start(iv_for_2nd_ct);
    dec->finish(second_ct);
    return second_ct;
}

cipher_block_t<AES_BLOCK_SIZE> ecb_encrypt_block(std::span<const uint8_t> key_span,
                                                 cipher_block_t<AES_BLOCK_SIZE> const& input)
{

    std::string cipher_spec = botan_aes_ecb_cipher_spec_from_key_byte_len(key_span.size());
    
    auto enc = Botan::BlockCipher::create(cipher_spec);
    if (enc == nullptr)
    {
        throw ::Exception("failed to set up Botan ECB encryption");
    }
    enc->set_key(key_span);
    std::vector<uint8_t> input_as_vec = input.to_uint8_vec();
    enc->encrypt(input_as_vec);
    return cipher_block_t<AES_BLOCK_SIZE>(input_as_vec);
}

cipher_block_vec_t<AES_BLOCK_SIZE> ecb_encrypt_blocks(std::span<const uint8_t> key_span, cipher_block_vec_t<AES_BLOCK_SIZE> const& input)
{
    cipher_block_vec_t<AES_BLOCK_SIZE> result;
    for(auto const& block : input)
    {
        result.push_back(ecb_encrypt_block(key_span, block));
    }
    return result;
} 
