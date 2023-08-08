#include "ocb-oracle.h"
#include "ocb-detail.h"

namespace
{

template <size_t B, typename T>
inline constexpr uint8_t get_byte(T input)
    requires(B < sizeof(T))
{
    const size_t shift = ((~B) & (sizeof(T) - 1)) << 3;
    return static_cast<uint8_t>((input >> shift) & 0xFF);
}
inline constexpr void store_be(uint64_t in, uint8_t out[8])
{
    out[0] = get_byte<0>(in);
    out[1] = get_byte<1>(in);
    out[2] = get_byte<2>(in);
    out[3] = get_byte<3>(in);
    out[4] = get_byte<4>(in);
    out[5] = get_byte<5>(in);
    out[6] = get_byte<6>(in);
    out[7] = get_byte<7>(in);
}

} // namespace

std::vector<uint8_t> determine_add_data_for_chunk(aead_packet_t const& aead,
                                                                     uint64_t const chunk_idx_non_final,
                                                                     bool const is_final_empty_chunk,
                                                                     uint64_t const total_bytes)
{
    uint64_t chunk_idx = chunk_idx_non_final;
    if(is_final_empty_chunk)
    {
        chunk_idx = aead.aead_chunks().size();
    }
    if (chunk_idx > aead.aead_chunks().size())
    {
        throw Exception("chunk idx out of range in AEAD packet");
    }
    //  new format encoding (bits 7 and 6 set, bits 5-0 carry the packet tag), version number, cipher algorithm octet,
    //  encryption mode octet, chunk size octet, and an eight-octet, big-endian chunk index as additional data
    //
    std::vector<uint8_t> result = {static_cast<uint8_t>(packet::tag_e::aead) | 0x80 | 0x40,
                                   1,
                                   static_cast<uint8_t>(aead.cipher()),
                                   static_cast<uint8_t>(aead.aead_type()),
                                   aead.chunk_size_octet()};
    uint32_t iv_len;
    switch (aead.aead_type())
    {
        case aead_type_e::ocb:
            iv_len = 15;
            break;
        case aead_type_e::eax:
            iv_len = 16;
            break;
        default:
            throw Exception("unknown AEAD mode");
    }

    uint64_t index = chunk_idx;

    std::vector<uint8_t> iv = aead.iv();
    if(iv.size() != iv_len)
    {
        throw Exception("invalid iv length for AEAD encountered");
    }

    switch (aead.aead_type())
    {
        // code take from RNP, specification for OCB missing in draft-koch
        case aead_type_e::ocb:
            for (int i = 14; (i >= 0) && index; i--)
            {
                iv[static_cast<uint8_t>(i)] ^= index & 0xff;
                index = index >> 8;
            }
            break;
        case aead_type_e::eax:
            for (int i = 15; (i > 7) && index; i--)
            {
                iv[static_cast<uint8_t>(i)] ^= index & 0xff;
                index = index >> 8;
            }
            break;
    }
    result.insert(result.end(), iv.begin(), iv.end());
    if (is_final_empty_chunk)
    {
        std::array<uint8_t, 8> total_encoded;
        store_be(total_bytes, total_encoded.data());
        result.insert(result.end(), total_encoded.begin(), total_encoded.end());
    }
    return result;
}

void ocb_attack_change_order_of_chunks(uint32_t iter,
                                       vector_cfb_ciphertext_t const& vec_ct,
                                       std::span<const uint8_t> pkesk,
                                       openpgp_app_decr_params_t app_aparam,
                                       std::span<const uint8_t> session_key,
                                       std::span<uint8_t> aead_packet_encoded,
                                        std::span<const uint8_t> encrypted_zero_block
                                       )
{
    std::string cipher_spec;
    aead_packet_t aead(aead_packet_encoded);
    if(aead.cipher() == cipher_e::aes_128)
    {
       cipher_spec = "AES-128";
    }
    else if(aead.cipher() == cipher_e::aes_256)
    {
        cipher_spec = "AES-256";
    }
    else
    {
        throw Exception("unsupported cipher type");
    }
    auto enc = Botan::BlockCipher::create(cipher_spec);
    L_computer computer(encrypted_zero_block);

    // TODO: swap the first and second chunk

    // query for the encryption of A_1 ⊕ F_1 ‖ … ‖ A_n ⊕ F_n ‖ A'_1 ⊕ F_1 ‖ … ‖ A'_{n'} ⊕ F_{n'}}

}
