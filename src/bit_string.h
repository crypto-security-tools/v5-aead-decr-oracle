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

    bit_string_t(bit_string_t const& other) : std::vector<uint8_t>(*static_cast<const std::vector<uint8_t>*>(&other))
    {
    }


    bit_string_t(std::vector<uint8_t> const& other) : std::vector<uint8_t>(other)
    {
    }

    std::vector<uint8_t> const& as_vector() const
    {
        return *static_cast<const std::vector<uint8_t>*>(this);
    }

    std::vector<uint8_t> & as_vector() 
    {
        return *static_cast<std::vector<uint8_t>*>(this);
    }

    bit_string_t& operator^=(const bit_string_t& rhs);

  private:
    std::vector<uint8_t> m_bytes;
};


#endif /* _BIT_STRING_H */
