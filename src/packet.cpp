#include "packet.h"
#include "except.h"

namespace packet
{
const std::map<tag_e, std::string> tag2str_map {
    {tag_e::pkesk, "PKESK"},
    {tag_e::signature, "SIG"},
    {tag_e::skesk, "SKESK"},
    {tag_e::ops, "OPS"},
    {tag_e::sec_key, "SECKEY"},
    {tag_e::pub_key, "PUBKEY"},
    {tag_e::sec_sub_key, "SECSUBKEY"},
    {tag_e::compressed_data, "COMP"},
    {tag_e::symm_encr_data, "SED"},
    {tag_e::marker, "MARKER"},
    {tag_e::literal_data, "LIT"},
    {tag_e::trust, "TRUST"},
    {tag_e::user_id, "UID"},
    {tag_e::pub_sub_key, "PUBSUBKEY"},
    {tag_e::user_attribute, "UAT"},
    {tag_e::seipd, "SEIPD"},
    {tag_e::mdc, "MDC"},
    {tag_e::aead, "AEAD"},
    {tag_e::padding, "PADDING"},

};

bool is_valid_packet_tag(uint8_t tag)
{
    for (auto const& key__value : tag2str_map)
    {
        if (static_cast<uint8_t>(key__value.first) == tag)
        {
            return true;
        }
    }
    return false;
}
} // namespace packet
using namespace packet;

packet_t::packet_t(tag_e raw_tag, header_format_e format) : m_raw_tag(raw_tag), m_format(format)
{
}


packet_t::~packet_t()
{
}


std::vector<uint8_t> packet_t::packet_header(size_t contents_length) const
{
    std::vector<uint8_t> v;
    if (m_format == header_format_e::legacy)
    {
        uint8_t len_type;
        uint8_t packet_tag_shifted = static_cast<uint8_t>(m_raw_tag) << 2;
        v.push_back(packet_tag_shifted);
        if(contents_length <= 255)
        {
            len_type = 0;
            v.push_back(contents_length);
        }
        else if(contents_length <= 0xFFFF)
        {
            len_type = 1;
            v.push_back(contents_length >> 8);
            v.push_back(contents_length);
        }
        else
        {
            throw Exception("old format packet header lengths > 0xFFFF are not implemented");
        }
        v[0] |= len_type | 0x80;
        // throw Exception("legacy header format not implemented");
    }
    else
    {
        v.push_back(0x80 | 0x40 | static_cast<uint8_t>(m_raw_tag));
        if (contents_length <= 191)
        {
            v.push_back(contents_length);
        }
        else if (contents_length <= 8383)
        {
            // bodyLen = ((1st_octet - 192) << 8) + (2nd_octet) + 192
            uint32_t len_to_encode = contents_length - 192;
            v.push_back((len_to_encode >> 8) + 192);
            v.push_back((len_to_encode & 0xFF));
        }
        else
        {
            // 0xFF as 1st octet, then bodyLen = (2nd_octet << 24) | (3rd_octet << 16) | (4th_octet << 8)  | 5th_octet
            v.push_back(0xFF);
            v.push_back(contents_length >> 24);
            v.push_back(contents_length >> 16);
            v.push_back(contents_length >> 8);
            v.push_back(contents_length);
        }
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
