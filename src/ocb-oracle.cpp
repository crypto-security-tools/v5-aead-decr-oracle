#include "ocb-oracle.h"
#include "ocb-detail.h"
#include "cipher_block.h"
#include "ocb-detail.h"
#include "assert_util.h"
#include "opgp_cfb_decr_fun_simulation.h"
#include <set>

namespace
{

template <size_t B, typename T>
inline constexpr uint8_t get_byte(T input)
    requires(B < sizeof(T))
{
    const size_t shift = ((~B) & (sizeof(T) - 1)) << 3;
    return static_cast<uint8_t>((input >> shift) & 0xFF);
}

inline constexpr void store64_be(uint64_t in, uint8_t out[8])
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

std::vector<uint8_t> determine_nonce_for_aead_chunk(aead_packet_t const& aead,
                                                  uint64_t const chunk_idx_non_final,
                                                  bool const is_final_empty_chunk) 
{
    std::vector<uint8_t> result;
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
    std::vector<uint8_t> iv = aead.iv();
    if (iv.size() != iv_len)
    {
        throw Exception("invalid iv length for AEAD encountered");
    }
    uint64_t chunk_idx = chunk_idx_non_final;
    if (is_final_empty_chunk)
    {
        // the final chunk is not part of the packet
        chunk_idx = aead.aead_chunks().size();
    }
    if (chunk_idx > aead.aead_chunks().size())
    {
        throw Exception("chunk idx out of range in AEAD packet");
    }

    uint64_t index = chunk_idx;
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
    return iv; 
}

std::vector<uint8_t> determine_add_data_for_chunk(aead_packet_t const& aead,
                                                  uint64_t const chunk_idx_non_final,
                                                  bool const is_final_empty_chunk,
                                                  uint64_t const total_bytes)
{
    uint64_t chunk_idx = chunk_idx_non_final;
    if (is_final_empty_chunk)
    {
        // the final chunk is not part of the packet
        chunk_idx = aead.aead_chunks().size();
    }
    else if(chunk_idx_non_final >= aead.aead_chunks().size())
    {
        throw Exception("index for non-final chunk is out of range");
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

    std::vector<uint8_t> encoded_idx(8);
    store64_be(chunk_idx_non_final, &encoded_idx[0]);
    result.insert(result.end(), encoded_idx.begin(), encoded_idx.end());

    if (is_final_empty_chunk)
    {
        std::array<uint8_t, 8> total_encoded;
        store64_be(total_bytes, total_encoded.data());
        result.insert(result.end(), total_encoded.begin(), total_encoded.end());
    }
    return result;
}

void ocb_attack_change_order_of_chunks(uint32_t iter,
                                       run_time_ctrl_t ctl,
                                       // vector_cfb_ciphertext_t const& vec_ct,
                                       vector_ct_t& vec_ct,
                                       std::span<const uint8_t> pkesk,
                                       std::span<const uint8_t> session_key,
                                       aead_packet_t const& aead_packet,
                                       std::span<const uint8_t> encrypted_zero_block,
                                       openpgp_app_decr_params_t const& decr_params,
                                       std::filesystem::path const& msg_file_path)
{
    std::string cipher_spec;
    if (aead_packet.cipher() == cipher_e::aes_128)
    {
        cipher_spec = "AES-128";
    }
    else if (aead_packet.cipher() == cipher_e::aes_256)
    {
        cipher_spec = "AES-256";
    }
    else
    {
        std::cerr << "AEAD packet:\n" << aead_packet.to_string() << "\n";
        throw Exception(std::format("unsupported cipher type {}", static_cast<uint8_t>(aead_packet.cipher())));
    }
    auto enc = Botan::BlockCipher::create(cipher_spec);
    L_computer l_computer(encrypted_zero_block);

    // TODO: swap the first and second chunk
    std::vector<aead_chunk_t> chunks = aead_packet.aead_chunks();
    std::cout << std::format("#chunks: {}\n", chunks.size());
    if (chunks.size() < 2)
    {
        throw Exception(
            "provided AEAD packet has less than two chunks, chunk swapping attack is thus impossible. Aborting.");
    }
    aead_chunk_t first_chunk_new  = chunks[0];
    aead_chunk_t second_chunk_new = chunks[1];
    if (first_chunk_new.encrypted.size() != second_chunk_new.encrypted.size())
    {
        throw Exception("attack is only designed for the case where the first two chunks are of the same length, this "
                        "is not the case here");
    }
    std::array<std::vector<uint8_t>, 2> add_data;
    add_data[0] = determine_add_data_for_chunk(aead_packet, 0);
    add_data[1] = determine_add_data_for_chunk(aead_packet, 1);

    std::cout << "add data lengths:\n";
    for(std::size_t idx : std::set<size_t>{0,1})
    {
       std::cout << std::format("  [{}]: {}\n", idx, add_data[idx].size()); 
    }

    // parse the add. data into full blocks and potentially trailing non-full block:
    std::array<cipher_block_vec_t<AES_BLOCK_SIZE>::full_blocks_and_trailing_t, 2> add_data_blocks_and_trail;
    add_data_blocks_and_trail[0] = cipher_block_vec_t<AES_BLOCK_SIZE>::parse_to_blocks_and_trailing(add_data[0]);
    add_data_blocks_and_trail[1] = cipher_block_vec_t<AES_BLOCK_SIZE>::parse_to_blocks_and_trailing(add_data[1]);

    if (add_data_blocks_and_trail[0].full_blocks.size() != add_data_blocks_and_trail[1].full_blocks.size())
    {
        throw Exception("additional data not of equal length for swapped chunks");
    }

    cipher_block_vec_t<AES_BLOCK_SIZE> F;
    F.push_back(cipher_block_t<AES_BLOCK_SIZE>()); // F_0 = [0]^{128}
    std::cout << std::format("#add data full blocks[0]: {}\n", add_data_blocks_and_trail[0].full_blocks.size());
    for (uint32_t i = 1; i < add_data_blocks_and_trail[0].full_blocks.size(); i++)
    {
        cipher_block_t<AES_BLOCK_SIZE> x(l_computer.get(var_ctz32(i))); // L_ntz(i)
        x ^= F[F.size() - 1];                                           // L_ntz(i) ⊕ F_{i-1}
        F.push_back(x);
    }
    // F_0 is not used for the actual computations
    F.erase(F.begin());

    // padd the non-full trailing blocks of the add. data:
    for (auto & ad_data : add_data_blocks_and_trail)
    {
        auto& trailing = ad_data.trailing;
        std::cout << std::format("trailing = {}\n", trailing.size());
        if (trailing.size() > 0)
        {
            // at least one byte smaller than the block size
            ad_data.trailing.push_back(0x80); // ‖ 1000 0000
            while (trailing.size() < AES_BLOCK_SIZE)
            {
                trailing.push_back(0);
            }
            // set the new full block:
            ad_data.full_blocks.push_back(trailing);
            trailing.resize(0);
            // compute the corresponding offset block:
            cipher_block_t<AES_BLOCK_SIZE> L_star = l_computer.star();
            if(F.size() < ad_data.full_blocks.size())
            {
                cipher_block_t<AES_BLOCK_SIZE> prev_block; // again F_0 = [0]¹²⁸
                if(F.size())
                { 
                   prev_block = F[F.size() - 1]; 
                }
                F.push_back(prev_block ^ L_star);
            }
        }
    }

    // verify lengths are matching
    if (add_data_blocks_and_trail[0].full_blocks.size() != F.size())
    {
        throw Exception(std::format("internal error: size of offsets ({}) and additional data ({}) is not matching", F.size(), add_data_blocks_and_trail[0].full_blocks.size()));
    }

    // query for the encryption of A_1 ⊕ F_1 ‖ … ‖ A_n ⊕ F_n ‖ A'_1 ⊕ F_1 ‖ … ‖ A'_{n'} ⊕ F_{n'}}:
    cipher_block_vec_t<AES_BLOCK_SIZE> oracle_ciphertext_blocks;
    for (size_t i = 0; i < F.size(); i++)
    {
        oracle_ciphertext_blocks.push_back(F[i] ^ add_data_blocks_and_trail[0].full_blocks[i]);
    }
    for (size_t i = 0; i < F.size(); i++)
    {
        oracle_ciphertext_blocks.push_back(F[i] ^ add_data_blocks_and_trail[1].full_blocks[i]);
    }


    assertm(vec_ct.leading_blocks().size() != 0, "leading blocks of vector ciphertext may not be empty");

    // no need to append another block (zero block) because the final CFB ciphertext block is not subject to block
    std::cout << "OCB chunk exchange attack: first oracle query ...\n";
    // decryption, this is done in the called function:
    cipher_block_vec_t<AES_BLOCK_SIZE> ecb_decr_blocks_from_oracle =
        invoke_ecb_opgp_decr(std::format("{}-ocb-exch-ord-of-chunks-att-init-query-pgp-msg", iter), ctl, vec_ct, oracle_ciphertext_blocks, pkesk, decr_params, session_key, msg_file_path);
    std::cout << "... OCB chunk exchange attack: first oracle query completed\n";

    std::cout << "... OCB chunk exchange attack is not completely implemented\n";
}
