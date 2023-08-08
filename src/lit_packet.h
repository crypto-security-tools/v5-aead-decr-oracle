#ifndef _LIT_PACKET_H
#define _LIT_PACKET_H

#include <vector>
#include <string>
#include <cstdint>
#include <span>
#include <format>
#include "packet.h"

class literal_data_packet_t : public packet_t
{

  public:
    enum class format_e
    {
        binary     = 'b',
        utf8       = 'u',
        local_mode = 'l',
        textual    = 0x74,
        mime       = 0x6d
    };
    literal_data_packet_t(format_e format, std::string_view filename, uint32_t date, std::span<uint8_t> data);

    std::vector<uint8_t> packet_contents() const override final;

    inline std::string to_string() const override
    {
       return std::format("LIT packet\n  format: {}\n  filename: '{}'\n  date: {}\n  content size: {}", static_cast<uint8_t>(m_format), m_filename, m_date, m_data.size());
    }


  private:
    std::vector<uint8_t> m_data;
    format_e m_format;
    std::string m_filename;
    uint32_t m_date;
};


#endif /* _LIT_PACKET_H */
