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
#include "packet.h"
#include "aead_packet.h"


using packet_parse_visitor_f =
    std::function<void(uint32_t packet_nb, std::string const& error_str, std::unique_ptr<packet_t> packet_up)>;

packet_sequence_t get_packet_sequence(std::vector<uint8_t> const& encoded_vec);

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
        std::string result = std::format("tag: {}\nbody length: {}", packet::tag2str_map.at(m_tag), m_body.size());
        return result;
    }

  private:
    packet::tag_e m_tag;
    std::vector<uint8_t> m_body;
};

inline std::unique_ptr<packet_t> create_packet(packet::tag_e tag,
                                        packet::header_format_e hdr_fmt,
                                        std::span<const uint8_t> body)
{
    using enum packet::tag_e;
    using enum packet::header_format_e;
    if (tag == aead)
    {
        return std::unique_ptr<packet_t>(new aead_packet_t(body, hdr_fmt));
    }
    return std::unique_ptr<generic_packet_t>(new generic_packet_t(tag, hdr_fmt, body));
}

#endif /* ____GENERIC_PACKET_H */
