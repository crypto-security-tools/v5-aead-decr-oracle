#include "lit_packet.h"


literal_data_packet_t::literal_data_packet_t(format_e format,
                                             std::string_view filename,
                                             uint32_t date,
                                             std::span<uint8_t> data)
    :packet_t(packet_t::raw_packet_tags_e::literal_data, packet_t::header_format_e::new_form), m_data(), m_format(format), m_filename(filename), m_date(date)
{
    m_data.assign(data.begin(), data.end());
}


std::vector<uint8_t> literal_data_packet_t::packet_contents() const
{

    std::vector<uint8_t> packet_contents;
    packet_contents.push_back(static_cast<uint8_t>(m_format));
    packet_contents.push_back(m_filename.size());
    packet_contents.insert(packet_contents.end(), m_filename.begin(), m_filename.end());
    packet_contents.push_back(m_date >> 24);
    packet_contents.push_back(m_date >> 16);
    packet_contents.push_back(m_date >> 8);
    packet_contents.push_back(m_date);

    packet_contents.insert(packet_contents.end(), m_data.begin(), m_data.end());

    return packet_contents;
}
