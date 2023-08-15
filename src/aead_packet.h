#ifndef _AEAD_PACKET_H
#define _AEAD_PACKET_H

#include <vector>
#include <string>
#include <cstdint>
#include <span>
#include <iostream>
#include <format>
#include "packet.h"
#include "except.h"

enum class aead_type_e
{
    ocb = 2,
    eax = 1
};

enum class cipher_e
{
  aes_128 = 7,
  aes_192 = 8,
  aes_256 = 9

};

inline std::string cipher_to_string(cipher_e ciph)
{
    using enum cipher_e;
    switch(ciph)
    {
        case aes_128:
            return "AES-128";
        case aes_192:
            return "AES-192";
        case aes_256:
            return "AES-256";
        default:
            throw Exception("invalid value for cipher_e");
    }
}

inline std::string aead_type_to_string(aead_type_e type)
{
    using enum aead_type_e;
    return type == ocb ? "OCB" : "EAX";
}


struct aead_chunk_t
{
    std::vector<uint8_t> encrypted;
    std::vector<uint8_t> auth_tag;
};

class aead_packet_t : public packet_t
{
  public:
    /**
     * @brief Create an AEAD packet from the encoded body contents
     *
     * @param encoded_body the packet body contents (excluding the packet header)
     */
    aead_packet_t(std::span<const uint8_t> encoded_body, packet::header_format_e hdr_fmt = packet::header_format_e::new_form);

    inline uint64_t chunk_size() const
    {
        size_t chunk_size = static_cast<uint64_t>(1) << (m_chunk_size_octet + 6);
        std::cout << std::format("computing from octet {} the chunksize {}\n", m_chunk_size_octet, chunk_size);
        return (chunk_size);
    }
    inline uint8_t chunk_size_octet() const
    {
        return m_chunk_size_octet;
    }

    inline void rewrite_chunk(aead_chunk_t const& chunk, uint32_t chunk_idx)
    {
        if(chunk_idx > m_chunks.size())
        {
            throw Exception("chunk idx for rewrite is out of range");
        }
        m_chunks[chunk_idx] = chunk;
    }

    inline std::vector<uint8_t> final_auth_tag() const
    {
        return m_final_auth_tag;
    }

    inline std::vector<uint8_t> iv() const
    {
        return m_iv;
    }

    inline aead_type_e aead_type() const
    {
        return m_aead_type;
    }

    inline cipher_e cipher() const
    {
        return m_cipher;
    }

    uint32_t plaintext_size() const;


    std::string to_string() const override;

    std::vector<aead_chunk_t> aead_chunks() const;

    virtual ~aead_packet_t();
  protected:
    std::vector<uint8_t> packet_contents() const override;


  private:
    aead_type_e m_aead_type;
    cipher_e m_cipher;
    std::vector<uint8_t> m_iv;
    uint8_t m_chunk_size_octet;
    //std::vector<uint8_t> m_ciphertext;
    std::vector<aead_chunk_t> m_chunks;
    std::vector<uint8_t> m_final_auth_tag;
};


#endif /* _AEAD_PACKET_H */
