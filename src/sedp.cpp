
#include "sedp.h"
#include <array>
#include <string>
#include <format>
#include <iostream>

#include <botan/cipher_mode.h>
#include <botan/hex.h>
#include "except.h"
#include "util.h"

symm_encr_data_packet_t::symm_encr_data_packet_t():packet_t(packet::tag_e::symm_encr_data) {

};



std::vector<uint8_t> symm_encr_data_packet_t::packet_contents() const
{

    return m_ciphertext;
}


// static
std::vector<uint8_t> symm_encr_data_packet_t::aes_sedp_encrypt_payload(std::span<const uint8_t> session_key,
                                                                       std::span<const uint8_t> plaintext,
                                                                       quick_check_spec_e quick_check_validity)
{

    const unsigned block_size = 16;
    // std::string key_len_str = "128";
#if 0
    if (session_key.size() != 16 && session_key.size() != 32)
    {

        throw Exception("invalid size for session key: " + std::to_string(session_key.size()));
    }
    // std::string cipher_spec("AES-128/CFB");
    std::string cipher_spec = std::format("AES-{}/CFB", session_key.size() * 8);
#endif
    std::string cipher_spec = botan_aes_cfb_cipher_spec_from_key_byte_len(session_key.size());
    std::vector<uint8_t> result;
    result.push_back(0x09 | 0xC0); // packet tag with *new packet format*

    std::vector<uint8_t> random_block_plus_two = {
        0x01, 0x02, 0xFB, 0xD3, 0x01, 0x02, 0xFB, 0xD3, 0x01, 0x02, 0xFB, 0xD3, 0x01, 0x02, 0xFB, 0xD3, 0xFB, 0xD3};

    if (quick_check_validity != quick_check_spec_e::valid)
    {
        random_block_plus_two[random_block_plus_two.size() - 1] -= 1;
    }

    auto dec = Botan::Cipher_Mode::create(cipher_spec, Botan::Cipher_Dir::Encryption);
    std::vector<uint8_t> zero_iv(block_size);
    dec->set_key(session_key);
    dec->start(zero_iv);
    dec->finish(random_block_plus_two);


    std::vector<uint8_t> second_iv(&random_block_plus_two[2], &random_block_plus_two[18]);

    dec->start(second_iv);
    std::vector<uint8_t> encrypted_data;
    encrypted_data.assign(plaintext.begin(), plaintext.end());
    dec->finish(encrypted_data);
    std::vector<uint8_t> opgp_ct;
    opgp_ct.insert(opgp_ct.end(), random_block_plus_two.begin(), random_block_plus_two.end());
    opgp_ct.insert(opgp_ct.end(), encrypted_data.begin(), encrypted_data.end());
    return opgp_ct;
}

// static
symm_encr_data_packet_t symm_encr_data_packet_t::create_sedp_from_plaintext(std::span<const uint8_t> plaintext,
                                                                            std::span<const uint8_t> session_key,
                                                                            quick_check_spec_e quick_check)
{
    symm_encr_data_packet_t result;
    // result.m_data.insert(result.m_data.end(), data.begin(), data.end());
    result.m_ciphertext = aes_sedp_encrypt_payload(session_key, plaintext, quick_check);
    result.m_session_key.assign(session_key.begin(), session_key.end());
    result.m_quick_check = quick_check;
    return result;
}

// static
symm_encr_data_packet_t symm_encr_data_packet_t::create_sedp_from_ciphertext(std::span<const uint8_t> ciphertext)
{
    symm_encr_data_packet_t result;
    result.m_ciphertext.assign(ciphertext.begin(), ciphertext.end());
    return result;
}
