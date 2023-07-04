#include "packet.h"
#include "except.h"

packet_t::packet_t(raw_packet_tags_e raw_tag, header_format_e format) : m_raw_tag(raw_tag), m_format(format)
{
}


packet_t::~packet_t()
{
}


std::vector<uint8_t> packet_t::packet_header(size_t contents_length) const
{
    std::vector<uint8_t> v;
    if (m_format != header_format_e::new_form)
    {
        throw Exception("legacy header format not implemented");
    }
    v.push_back(0x80 | 0x40 | static_cast<uint8_t>(m_raw_tag));
    if (contents_length <= 191)
    {
        v.push_back(contents_length);
    }
    else if (contents_length <= 8383)
    {
        // bodyLen = ((1st_octet - 192) << 8) + (2nd_octet) + 192
        v.push_back((contents_length >> 8) + 192);
        v.push_back((contents_length & 0xFF) - 192);
    }
    else
    {
        throw Exception("packets with more than two octet length are not supported");
    }
    return v;
}


std::vector<uint8_t> packet_t::get_encoded() const
{
    auto contents = packet_contents();
    auto result   = packet_header(contents.size());
    result.insert(result.end(), contents.begin(), contents.end());
    return result;
}
