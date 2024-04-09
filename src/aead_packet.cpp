

#include "aead_packet.h"
#include "botan/hex.h"
#include "except.h"
#include <algorithm>
#include <format>
#include <cassert>
#include <iostream>

namespace
{

std::vector<aead_chunk_t> whole_ciphertext_excluding_final_tag_to_aead_chunks(std::span<const uint8_t> whole_ciphertext,
                                                          uint64_t chunk_size)
{
    uint32_t i                   = 0;
    const uint32_t auth_tag_size = 16;
    std::vector<aead_chunk_t> result;
    if(whole_ciphertext.size() < auth_tag_size)
    {
        throw Exception("ciphertext must at least contain the final authentication tag");
    }
    while (i < whole_ciphertext.size()) // we want to leave the auth tag of the final chunk without data
    {
        size_t rem_len = whole_ciphertext.size() - i;
        
        size_t this_chunk_size_plus_auth_tag =
            std::min(static_cast<size_t>(chunk_size + auth_tag_size), whole_ciphertext.size() - i); 
        
        if (this_chunk_size_plus_auth_tag < auth_tag_size)
        {
            throw Exception(std::format("internal error: combined chunk size too small to contain authentication tag: {}", this_chunk_size_plus_auth_tag));
        }
        size_t this_chunk_size = this_chunk_size_plus_auth_tag - auth_tag_size;
        result.push_back(
            {.encrypted = std::vector<uint8_t>(&whole_ciphertext[i], &whole_ciphertext[i + this_chunk_size]),
             .auth_tag  = std::vector<uint8_t>(&whole_ciphertext[i + this_chunk_size],
                                              &whole_ciphertext[i + this_chunk_size + auth_tag_size])});
        i += this_chunk_size + auth_tag_size;
    }
    if (i != whole_ciphertext.size())
    {
        throw Exception(std::format("internal error in chunk parsing: i = {}, whole_ciphertext size = {}", i, whole_ciphertext.size()));
    }

    return result;
}

std::vector<uint8_t> encode_aead_chunks(std::vector<aead_chunk_t> const& chunks, uint64_t chunk_size)
{
    std::vector<uint8_t> result;
    for (size_t i = 0; i < chunks.size(); i++)
    {
        aead_chunk_t const& c = chunks[i];

        if (c.encrypted.size() > chunk_size || (i != chunks.size() - 1 && c.encrypted.size() < chunk_size))
        {
            throw Exception("aead chunk for encoding has invalid chunk size");
        }

        result.insert(result.end(), c.encrypted.begin(), c.encrypted.end());
        result.insert(result.end(), c.auth_tag.begin(), c.auth_tag.end());
    }
    return result;
}

} // namespace

aead_packet_t::~aead_packet_t()
{
}

aead_packet_t::aead_packet_t(std::span<const uint8_t> encoded, packet::header_format_e hdr_fmt)
    : packet_t(packet::tag_e::aead, hdr_fmt)
{
    const uint32_t auth_tag_size = 16;
    using enum aead_type_e;
    if (encoded.size() < 37)
    {
        throw Exception("invalid body length for v5 AEAD packet");
    }
    if (encoded[0] != 1)
    {
        throw Exception(std::format("invalid version number for AEAD packet: {}", encoded[0]));
    }
    uint8_t cipher_octet = encoded[1];
    if (cipher_octet != 7 && cipher_octet != 8 && cipher_octet != 9)
    {
        throw Exception(std::format("unsupported cipher octet {}", cipher_octet));
    }
    m_cipher         = static_cast<cipher_e>(cipher_octet);
    m_aead_type      = static_cast<aead_type_e>(encoded[2]);
    uint32_t iv_size = 15;
    switch (m_aead_type)
    {
        case ocb:
            break;
        case eax:
            if (encoded.size() < 38)
            {
                throw Exception("invalid body length for v5 EAX AEAD packet");
            }
            iv_size = 16;
            break;
        default:
            throw Exception("invalid value for AEAD type");
    }
    this->m_chunk_size_octet = encoded[3];
    this->m_iv.assign(&encoded[4], &encoded[4 + iv_size]);
    std::vector<uint8_t> ciphertext(&encoded[4 + iv_size], &encoded[encoded.size() - auth_tag_size]);
    m_chunks = whole_ciphertext_excluding_final_tag_to_aead_chunks(ciphertext, chunk_size());
    this->m_final_auth_tag.assign(&encoded[encoded.size() - auth_tag_size], &encoded[encoded.size()]);
}

std::vector<aead_chunk_t> aead_packet_t::aead_chunks() const
{
    return m_chunks;
}

std::vector<uint8_t> aead_packet_t::packet_contents() const
{
    std::vector<uint8_t> result;
    result.push_back(1); // version nr.
    result.push_back(static_cast<uint8_t>(m_cipher));
    result.push_back(static_cast<uint8_t>(m_aead_type));
    result.push_back(m_chunk_size_octet);
    result.insert(result.end(), m_iv.begin(), m_iv.end());
    auto encoded_chunks = encode_aead_chunks(m_chunks, chunk_size());
    result.insert(result.end(), encoded_chunks.begin(), encoded_chunks.end());
    result.insert(result.end(), m_final_auth_tag.begin(), m_final_auth_tag.end());
    return result;
}

uint32_t aead_packet_t::plaintext_size() const
{
    uint32_t result = 0;
    for (auto& c : m_chunks)
    {
        result += c.encrypted.size();
    }
    return result;
}

std::string aead_packet_t::to_string() const
{
    std::string result = std::format(
        "AEAD packet\n  aead-type: {}\n  cipher = {}\n  chunk size: {}\n  overall plaintext size: {}\n  #chunks: {}\n",
        aead_type_to_string(m_aead_type),
        cipher_to_string(m_cipher),
        chunk_size(),
        plaintext_size(),
        aead_chunks().size());
    uint32_t cnt = 0;
    for (auto const& chunk : this->aead_chunks())
    {
        result += std::format(" chunk #{}:\n", cnt++);
        result += std::format(
            "     encrypted size: {}\n     auth tag size: {}\n ", chunk.encrypted.size(), chunk.auth_tag.size());
        result += std::format(
            "     encrypted = {}\n      auth tag = {}\n", Botan::hex_encode(chunk.encrypted), Botan::hex_encode(chunk.auth_tag));
    }
    return result;
}
