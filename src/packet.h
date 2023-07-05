#ifndef _PACKET_H
#define _PACKET_H

#include <vector>
#include <string>
#include <cstdint>
#include <span>

class packet_t
{
  public:
    enum class raw_packet_tags_e
    {
        literal_data   = 0x0b,
        symm_encr_data = 0x09
    };
    enum class header_format_e
    {
        legacy,
        new_form
    };
    packet_t(raw_packet_tags_e raw_tag, header_format_e format = header_format_e::new_form);
    std::vector<uint8_t> get_encoded() const;
    ~packet_t();

  protected:
    virtual std::vector<uint8_t> packet_contents() const = 0;

  private:
    std::vector<uint8_t> packet_header(size_t contents_length) const;
    raw_packet_tags_e m_raw_tag;
    header_format_e m_format;
};

#endif /* _PACKET_H */
