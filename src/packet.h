#ifndef _PACKET_H
#define _PACKET_H

#include <vector>
#include <string>
#include <cstdint>
#include <span>
#include <map>
#include <memory>

namespace packet
{
enum class tag_e
{
    pkesk           = 1,
    signature       = 2,
    skesk           = 3,
    ops             = 4,
    sec_key         = 5,
    pub_key         = 6,
    sec_sub_key     = 7,
    compressed_data = 8,
    symm_encr_data  = 9,
    marker          = 10,
    literal_data    = 11,
    trust           = 12,
    user_id         = 13,
    pub_sub_key     = 14,
    user_attribute  = 15,
    seipd           = 18,
    mdc             = 19,
    aead            = 20,
    padding         = 21,
};

enum class header_format_e
{
    legacy,
    new_form
};
extern const std::map<tag_e, std::string> tag2str_map;

bool is_valid_packet_tag(uint8_t tag);
} // namespace packet


class packet_t
{
  public:
    packet_t(packet::tag_e raw_tag, packet::header_format_e format = packet::header_format_e::new_form);
    std::vector<uint8_t> get_encoded() const;
    packet_t(std::span<const uint8_t> encoded);
    ~packet_t();

    inline packet::tag_e raw_tag() const
    {
        return m_raw_tag;
    }

    inline uint32_t body_length() const
    {
        return packet_contents().size();
    }
    virtual std::string to_string() const = 0;

  protected:
    virtual std::vector<uint8_t> packet_contents() const = 0;

  private:
    std::vector<uint8_t> packet_header(size_t contents_length) const;
    packet::tag_e m_raw_tag;
    packet::header_format_e m_format;
};

class packet_sequence_t : public std::vector<std::unique_ptr<packet_t>>
{
  public:
    inline std::string to_string() const
    {
        std::string result;
        for (auto const& p : *this)
        {
            result += p->to_string() + "\n";
        }
        return result;
    }

    inline std::vector<uint8_t> get_encoded() const
    {
        std::vector<uint8_t> result;
        for (auto const& ptr : *this)
        {
            auto that_encoded = ptr->get_encoded();
            result.insert(result.end(), that_encoded.begin(), that_encoded.end());
        }
        return result;
    }
};

#endif /* _PACKET_H */
