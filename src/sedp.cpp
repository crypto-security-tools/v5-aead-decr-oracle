
#include "sedp.h"
#include <array>
#include <string>
#include <format>

#include <botan/cipher_mode.h>
#include <botan/hex.h>
#include "except.h"

symm_encr_data_packet_t::symm_encr_data_packet_t() {

};

void encode_packet_length(std::vector<uint8_t>& v, size_t length)
{
    if (length <= 191)
    {
        v.push_back(length);
    }
    else if (length <= 8383)
    {
        // bodyLen = ((1st_octet - 192) << 8) + (2nd_octet) + 192
        v.push_back((length >> 8) + 192);
        v.push_back((length & 0xFF) - 192);
    }
}


std::vector<uint8_t> symm_encr_data_packet_t::get_encoded() const
{
    const unsigned block_size = 16;
    //std::string key_len_str = "128";
    if(m_session_key.size() != 16 && m_session_key.size() != 32)
    {
        
        throw Exception("invalid size for session key: " + std::to_string(m_session_key.size()));
    }
    //std::string cipher_spec("AES-128/CFB");
    std::string cipher_spec = std::format("AES-{}/CFB", m_session_key.size() * 8);
    std::vector<uint8_t> result;
    result.push_back(0x09 | 0xC0); // packet tag with *new packet format*

    std::vector<uint8_t> random_block_plus_two = {
        0x01, 0x02, 0xFB, 0xD3, 0x01, 0x02, 0xFB, 0xD3, 0x01, 0x02, 0xFB, 0xD3, 0x01, 0x02, 0xFB, 0xD3, 0xFB, 0xD3};

    auto dec = Botan::Cipher_Mode::create(cipher_spec, Botan::Cipher_Dir::Encryption);
    std::vector<uint8_t> zero_iv(block_size);
    dec->set_key(m_session_key);
    dec->start(zero_iv);
    dec->finish(random_block_plus_two); 
    
    
    std::vector<uint8_t> second_iv(&random_block_plus_two[2], &random_block_plus_two[18]);
    
    dec->start(second_iv);
    std::vector<uint8_t> encrypted_data(m_data);
    dec->finish(encrypted_data);

    std::vector<uint8_t> opgp_ct; 
    opgp_ct.insert(opgp_ct.end(), random_block_plus_two.begin(), random_block_plus_two.end());
    opgp_ct.insert(opgp_ct.end(), encrypted_data.begin(), encrypted_data.end());


    encode_packet_length(result, opgp_ct.size());
    result.insert(result.end(), opgp_ct.begin(), opgp_ct.end());
     
    return result;
}

// static
symm_encr_data_packet_t symm_encr_data_packet_t::create_sedp(std::span<uint8_t> const& data,
                                                             std::span<uint8_t> session_key)
{
    symm_encr_data_packet_t result;
    result.m_data.insert(result.m_data.end(), data.begin(), data.end());
    result.m_session_key.insert(result.m_session_key.end(), session_key.begin(), session_key.end());
    return result;
}
