#ifndef ____GENERIC_PACKET_H
#define ____GENERIC_PACKET_H

#include <vector>
#include <string>
#include <cstdint>
#include <span>
#include <map>
#include <deque>
#include <functional>
#include <memory>
#include <format>
#include <botan/hex.h>
#include <iostream>
#include "packet.h"
#include "aead_packet.h"


/*using packet_parse_visitor_f =
    std::function<void(uint32_t packet_nb, std::string const& error_str, std::unique_ptr<packet_t> packet_up)>;*/

packet_sequence_t parse_packet_sequence(std::vector<uint8_t> const& encoded_vec);

class generic_packet_t : public packet_t
{
  public:
    inline generic_packet_t(packet::tag_e raw_tag, packet::header_format_e hdr_fmt, std::span<const uint8_t> body)
        : packet_t(raw_tag, hdr_fmt), m_body(body.begin(), body.end())
    {
    }
    inline std::vector<uint8_t> packet_contents() const override
    {
        return m_body;
    }

    inline std::string to_string() const override
    {
        if(!packet::is_valid_packet_tag(static_cast<uint8_t>(packet_t::raw_tag())))
        {
            throw Exception(std::format("internal error: invalid packet tag {}", static_cast<uint8_t>(packet_t::raw_tag())));
        }
        std::string result = std::format("{} packet\n  body length: {}", packet::tag2str_map.at(packet_t::raw_tag()), m_body.size());
        return result;
    }

  private:
    std::vector<uint8_t> m_body;
};

inline std::unique_ptr<packet_t> create_packet(packet::tag_e tag,
                                        packet::header_format_e hdr_fmt,
                                        std::span<const uint8_t> body)
{
    using enum packet::tag_e;
    using enum packet::header_format_e;
    //uint8_t raw_tag_byte = static_cast<uint8_t>(tag);
    if (tag == aead)
    {
        return std::unique_ptr<packet_t>(new aead_packet_t(body, hdr_fmt));
    }
    return std::unique_ptr<generic_packet_t>(new generic_packet_t(tag, hdr_fmt, body));
}

#endif /* ____GENERIC_PACKET_H */
