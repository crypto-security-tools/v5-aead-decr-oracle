#include "eax_utils.h"
#include "stdint.h"
#include <vector>
#include <stdexcept>

void store_be64(uint8_t out[8], uint64_t in)
{
    out[0] = (uint8_t)(in >> 56) & 0xff;
    out[1] = (uint8_t)(in >> 48) & 0xff;
    out[2] = (uint8_t)(in >> 40) & 0xff;
    out[3] = (uint8_t)(in >> 32) & 0xff;
    out[4] = (uint8_t)(in >> 24) & 0xff;
    out[5] = (uint8_t)(in >> 16) & 0xff;
    out[6] = (uint8_t)(in >> 8) & 0xff;
    out[7] = (uint8_t)(in >> 0) & 0xff;
}

// https://www.ietf.org/archive/id/draft-koch-openpgp-2015-rfc4880bis-02.html#name-eax-mode
/* The nonce for EAX mode is computed by treating the starting initialization vector as a 16-octet, big-endian value and exclusive-oring the low eight octets of it with the chunk index. */
std::vector<uint8_t> compute_eax_nonce(std::vector<uint8_t> iv, std::vector<uint8_t> chunk_idx) 
{
    if(iv.size() != 16)
    {
        throw std::invalid_argument("IV size must be 16 for EAX nonce computation");
    }
    if(chunk_idx.size() != 8)
    {
        throw std::invalid_argument("IV size must be 16 for EAX nonce computation");
    }

    std::vector<uint8_t> result = iv;
    for(size_t i = 0; i < result.size(); i++)
    {
        result[i+8] ^= chunk_idx[i];
    }

    return result;
}