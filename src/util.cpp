
#include <format>
#include "util.h"
#include "except.h"

std::string botan_aes_cfb_cipher_spec_from_key_byte_len(unsigned key_byte_len)
{

    if (key_byte_len!= 16 && key_byte_len != 32)
    {

        throw Exception("invalid size for session key: " + std::to_string(key_byte_len));
    }
    // std::string cipher_spec("AES-128/CFB");
    std::string cipher_spec = std::format("AES-{}/CFB", key_byte_len * 8);
    return cipher_spec;
}

void lenght_is_multiple_of_aes_block_size_or_throw(std::span<const uint8_t> x)
{
    if(x.size() % 16)
    {
        throw Exception("provided data is not a multiple of the AES block length");
    }
}
