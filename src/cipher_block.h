#ifndef _CIPHER_BLOCK_H
#define _CIPHER_BLOCK_H


#include <vector>
#include <array>
#include <cstdint>
#include <iostream>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include "except.h"

template <uint8_t BLOCK_SIZE> class cipher_block_t : public std::array<uint8_t, BLOCK_SIZE>
{
  public:
    inline cipher_block_t<BLOCK_SIZE>& operator^=(cipher_block_t<BLOCK_SIZE> const& other)
    {
        for (unsigned i = 0; i < BLOCK_SIZE; i++)
        {
            this[i] ^= other[i];
        }
        return *this;
    }
    inline void randomize(Botan::AutoSeeded_RNG& rng)
    {

        rng.randomize(&(*this)[0], BLOCK_SIZE);
    }


  private:
};

template<uint8_t BLOCK_SIZE> class cipher_block_vec_t : public std::vector<cipher_block_t<BLOCK_SIZE>>
{
    public:
       inline cipher_block_vec_t()
           :std::vector<cipher_block_t<BLOCK_SIZE>>()
       {
       }
       inline cipher_block_vec_t(std::vector<cipher_block_t<BLOCK_SIZE>> const& vec)
          : std::vector<cipher_block_t<BLOCK_SIZE>>(vec)
       {
       }

       inline size_t byte_length() const
       {
         return this->size() * BLOCK_SIZE;
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
