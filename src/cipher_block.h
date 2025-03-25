#ifndef _CIPHER_BLOCK_H
#define _CIPHER_BLOCK_H


#include <vector>
#include <array>
#include <cstdint>
#include <iostream>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include "except.h"


#define AES_BLOCK_SIZE 16

template <uint8_t BLOCK_SIZE> class cipher_block_t : public std::array<uint8_t, BLOCK_SIZE>
{
  public:
    inline cipher_block_t<BLOCK_SIZE>()
    {
        std::memset(&this[0], 0, BLOCK_SIZE);
    }

    inline cipher_block_t<BLOCK_SIZE>(std::vector<uint8_t> const& rhs)
    {
        if (rhs.size() != BLOCK_SIZE)
        {
            throw Exception("trying to assign vector<uint8_t> of invalid length to cipher_block_t");
        }
        std::memcpy(&this[0], &rhs[0], BLOCK_SIZE);
    }

    inline cipher_block_t<BLOCK_SIZE>(std::span<const uint8_t> rhs)
    {
        if (rhs.size() != BLOCK_SIZE)
        {
            throw Exception("trying to assign span<uint8_t> of invalid length to cipher_block_t");
        }
        std::memcpy(&this[0], &rhs[0], BLOCK_SIZE);
    }

    inline cipher_block_t<BLOCK_SIZE>& operator^=(cipher_block_t<BLOCK_SIZE> const& other)
    {
        for (unsigned i = 0; i < BLOCK_SIZE; i++)
        {
            (*this)[i] ^= other[i];
        }
        return *this;
    }

    inline void randomize(Botan::AutoSeeded_RNG& rng)
    {

        rng.randomize(&(*this)[0], BLOCK_SIZE);
    }

    inline cipher_block_t& operator=(std::vector<uint8_t> const& rhs)
    {
        if (rhs.size() != BLOCK_SIZE)
        {
            throw Exception("trying to assign vector<uint8_t> of invalid length to cipher_block_t");
        }
        std::memcpy(&this[0], &rhs[0], BLOCK_SIZE);
        return *this;
    }

    inline std::vector<uint8_t> to_uint8_vec() const
    {
        return std::vector<uint8_t>(this->begin(), this->end());
    }

    inline std::string hex() const
    {
        return Botan::hex_encode(this->data(), this->size());
    }


  private:
};

template <uint8_t BLOCK_SIZE> class cipher_block_vec_t : public std::vector<cipher_block_t<BLOCK_SIZE>>
{
  public:
    struct full_blocks_and_trailing_t
    {
        cipher_block_vec_t<BLOCK_SIZE> full_blocks;
        std::vector<uint8_t> trailing;
    };

    inline cipher_block_vec_t() : std::vector<cipher_block_t<BLOCK_SIZE>>()
    {
    }

    inline cipher_block_vec_t(std::vector<cipher_block_t<BLOCK_SIZE>> const& vec)
        : std::vector<cipher_block_t<BLOCK_SIZE>>(vec)
    {
    }

    inline cipher_block_vec_t(std::span<const uint8_t> vec) : std::vector<cipher_block_t<BLOCK_SIZE>>()
    {
        if (vec.size() % BLOCK_SIZE)
        {
            throw Exception("trying to create cipher_block_vec_t from data which is not a multiple of the block size");
        }
        std::cout << "cipher_block_vec_t(std::span<const uint8_t> vec)\n";
        for (size_t i = 0; i < vec.size(); i += BLOCK_SIZE)
        {
            this->push_back(cipher_block_t<BLOCK_SIZE>(std::span(vec.begin() + i, vec.begin() + i + BLOCK_SIZE)));
        }
    }

    inline std::vector<uint8_t> serialize() const 
    {
        std::vector<uint8_t> result;
        for(auto const& b : *this)
        {
            result.insert(result.end(), b.begin(), b.end());
        }
        return result;
    }

    inline std::string hex() const
    {
        std::string result;
        for (auto x : *this)

        {
            if (result.size())
            {
                result += " ";
            }
            result += x.hex();
        }
        return result;
    }

    inline size_t byte_length() const
    {
        return this->size() * BLOCK_SIZE;
    }

    inline static full_blocks_and_trailing_t parse_to_blocks_and_trailing(std::span<const uint8_t> x)
    {
        full_blocks_and_trailing_t result;
        size_t i = 0;
        for (; i + BLOCK_SIZE <= x.size(); i += BLOCK_SIZE)
        {
            result.full_blocks.push_back(std::span(&x[i], &x[i + BLOCK_SIZE]));
        }
        result.trailing.assign(x.begin() + static_cast<long>(i), x.end());
        return result;
    }
};

template <uint8_t BLOCK_SIZE>
inline cipher_block_t<BLOCK_SIZE> operator^(cipher_block_t<BLOCK_SIZE> const& lhs,
                                            cipher_block_t<BLOCK_SIZE> const& rhs)
{
    cipher_block_t<BLOCK_SIZE> result;
    for (unsigned i = 0; i < BLOCK_SIZE; i++)
    {
        result[i] = lhs[i] ^ rhs[i];
    }
    return result;
}

namespace cipher_block
{

template <uint8_t BLOCK_SIZE>
void append_cb_vec_to_uint8_vec(std::vector<cipher_block_t<BLOCK_SIZE>> const& cbv, std::vector<uint8_t>& out)
{

    for (cipher_block_t<BLOCK_SIZE> const& x : cbv)
    {
        std::copy(x.begin(), x.end(), std::back_inserter(out));
    }
}

template <uint8_t BLOCK_SIZE> std::vector<uint8_t> cb_vec_to_uint8_vec(cipher_block_t<BLOCK_SIZE> const& cbv)
{
    std::vector<uint8_t> result;
    append_cb_vec_to_uint8_vec(cbv, result);
    return result;
}

template <uint8_t BLOCK_SIZE> std::vector<cipher_block_t<BLOCK_SIZE>> uint8_span_to_cb_vec(std::span<const uint8_t> s)
{
    if (s.size() % BLOCK_SIZE)
    {
        throw Exception("provided uint8_t span has size that is not a multiple of the block size");
    }
    std::vector<cipher_block_t<BLOCK_SIZE>> result;
    for (std::size_t i = 0; i < s.size(); i += BLOCK_SIZE)
    {
        cipher_block_t<BLOCK_SIZE> block;
        std::memcpy(&block[0], &s[i], BLOCK_SIZE);
        result.push_back(block);
    }
    return result;
}

} // namespace cipher_block

#endif /* _CIPHER_BLOCK_H */
