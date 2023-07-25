
#include <format>
#include "util.h"
#include "except.h"

namespace {
std::string botan_aes_cipher_spec_part_from_key_byte_len(unsigned key_byte_len)
{

    if (key_byte_len!= 16 && key_byte_len != 32)
    {

        throw Exception("invalid size for session key: " + std::to_string(key_byte_len));
    }
    // std::string cipher_spec("AES-128/CFB");
    std::string cipher_spec = std::format("AES-{}", key_byte_len * 8);
    return cipher_spec;
}
}

std::string botan_aes_cfb_cipher_spec_from_key_byte_len(unsigned key_byte_len)
{
  return botan_aes_cipher_spec_part_from_key_byte_len(key_byte_len) + "/CFB";
}
std::string botan_aes_ecb_cipher_spec_from_key_byte_len(unsigned key_byte_len)
{
  return botan_aes_cipher_spec_part_from_key_byte_len(key_byte_len); //+ "ECB/NoPadding";
}

void lenght_is_multiple_of_aes_block_size_or_throw(std::span<const uint8_t> x)
{
    if(x.size() % 16)
    {
        throw Exception("provided data is not a multiple of the AES block length");
    }
}
