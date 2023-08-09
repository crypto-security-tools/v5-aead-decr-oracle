/*
 *
 * Bit/Word Operations
 * (C) 1999-2008 Jack Lloyd
 * (C) Copyright Projet SECRET, INRIA, Rocquencourt
 * (C) Bhaskar Biswas and  Nicolas Sendrier
 * (C) 2014 cryptosource GmbH
 * (C) 2014 Falko Strenzke fstrenzke@cryptosource.de
 *
 * OCB Mode
 * (C) 2013,2017 Jack Lloyd
 * (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */


#ifndef _OCB_DETAIL_H
#define _OCB_DETAIL_H

#include <type_traits>
#include <cstdint>

#include <botan/block_cipher.h>
#include <botan/internal/poly_dbl.h>

/**
 * If top bit of arg is set, return ~0. Otherwise return 0.
 */
template <typename T>
inline constexpr T expand_top_bit(T a)
    requires(std::is_integral<T>::value)
{
    return static_cast<T>(0) - (a >> (sizeof(T) * 8 - 1));
}

/**
 * If arg is zero, return ~0. Otherwise return 0
 */
template <typename T>
inline constexpr T ct_is_zero(T x)
    requires(std::is_integral<T>::value)
{
    return expand_top_bit<T>(~x & (x - 1));
}

/**
 * Count the trailing zero bits in n
 * @param n an integer value
 * @return maximum x st 2^x divides n
 */
template <typename T>
inline constexpr std::size_t ctz(T n)
    requires(std::is_integral<T>::value)
{
    /*
     * If n == 0 then this function will compute 8*sizeof(T)-1, so
     * initialize lb to 1 if n == 0 to produce the expected result.
     */
    std::size_t lb = ct_is_zero(n) & 1;

    for (std::size_t s = 8 * sizeof(T) / 2; s > 0; s /= 2)
    {
        const T mask        = (static_cast<T>(1) << s) - 1;
        const std::size_t z = s * (ct_is_zero(n & mask) & 1);
        lb += z;
        n >>= z;
    }

    return lb;
}

inline constexpr std::size_t var_ctz32(uint32_t n)
{
    return ctz<uint32_t>(n);
}


class L_computer final
{
  public:
    explicit L_computer(const Botan::BlockCipher& cipher)
        : m_BS(cipher.block_size()), m_max_blocks(cipher.parallel_bytes() / m_BS)
    {
        m_L_star.resize(m_BS);
        cipher.encrypt(m_L_star);
        m_L_dollar = poly_double(star());
        m_L.push_back(poly_double(dollar()));

        while (m_L.size() < 8)
        {
            m_L.push_back(poly_double(m_L.back()));
        }

        m_offset_buf.resize(m_BS * m_max_blocks);
    }


    explicit L_computer(std::span<const uint8_t> encrypted_zero_block)
        : m_BS(encrypted_zero_block.size()), m_max_blocks(10000)
    { // arbitrary high value for m_max_blocks
        m_L_star.assign(encrypted_zero_block.begin(), encrypted_zero_block.end());
        // cipher.encrypt(m_L_star);
        m_L_dollar = poly_double(star());
        m_L.push_back(poly_double(dollar()));

        while (m_L.size() < 8)
        {
            m_L.push_back(poly_double(m_L.back()));
        }

        m_offset_buf.resize(m_BS * m_max_blocks);
    }

    void init(const std::vector<uint8_t>& offset)
    {
        m_offset = offset;
    }

    bool initialized() const
    {
        return m_offset.empty() == false;
    }

    const std::vector<uint8_t>& star() const
    {
        return m_L_star;
    }

    const std::vector<uint8_t>& dollar() const
    {
        return m_L_dollar;
    }

    const std::vector<uint8_t>& offset() const
    {
        return m_offset;
    }

    const std::vector<uint8_t>& get(size_t i) const
    {
        while (m_L.size() <= i)
        {
            m_L.push_back(poly_double(m_L.back()));
        }

        return m_L[i];
    }

    const uint8_t* compute_offsets(size_t block_index, size_t blocks)
    {
        BOTAN_ASSERT(blocks <= m_max_blocks, "OCB offsets");

        uint8_t* offsets = m_offset_buf.data();

        if (block_index % 4 == 0)
        {
            const std::vector<uint8_t>& L0 = get(0);
            const std::vector<uint8_t>& L1 = get(1);

            while (blocks >= 4)
            {
                // ntz(4*i+1) == 0
                // ntz(4*i+2) == 1
                // ntz(4*i+3) == 0
                block_index += 4;
                const size_t ntz4 = var_ctz32(static_cast<uint32_t>(block_index));

                Botan::xor_buf(offsets, m_offset.data(), L0.data(), m_BS);
                offsets += m_BS;

                Botan::xor_buf(offsets, offsets - m_BS, L1.data(), m_BS);
                offsets += m_BS;

                Botan::xor_buf(m_offset.data(), L1.data(), m_BS);
                Botan::copy_mem(offsets, m_offset.data(), m_BS);
                offsets += m_BS;

                Botan::xor_buf(m_offset.data(), get(ntz4).data(), m_BS);
                Botan::copy_mem(offsets, m_offset.data(), m_BS);
                offsets += m_BS;

                blocks -= 4;
            }
        }

        for (size_t i = 0; i != blocks; ++i)
        { // could be done in parallel
            const size_t ntz = var_ctz32(static_cast<uint32_t>(block_index + i + 1));
            Botan::xor_buf(m_offset.data(), get(ntz).data(), m_BS);
            Botan::copy_mem(offsets, m_offset.data(), m_BS);
            offsets += m_BS;
        }

        return m_offset_buf.data();
    }

  private:
    static std::vector<uint8_t> poly_double(const std::vector<uint8_t>& in)
    {
        std::vector<uint8_t> out(in.size());
        Botan::poly_double_n(out.data(), in.data(), out.size());
        return out;
    }

    const size_t m_BS, m_max_blocks;
    std::vector<uint8_t> m_L_dollar, m_L_star;
    std::vector<uint8_t> m_offset;
    mutable std::vector<std::vector<uint8_t>> m_L;
    std::vector<uint8_t> m_offset_buf;
};

#endif /* _OCB_DETAIL_H */
