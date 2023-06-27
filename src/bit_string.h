#ifndef _BIT_STRING_H
#define _BIT_STRING_H

#include <stdint.h>
#include <vector>

class bit_string_t : public std::vector<uint8_t>
{
  public:
    bit_string_t(std::size_t byte_len) : m_bytes(byte_len)
    {
    }

    bit_string_t& operator^=(const bit_string_t& rhs);

  private:
    std::vector<uint8_t> m_bytes;
};


#endif /* _BIT_STRING_H */
