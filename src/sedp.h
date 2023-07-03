#ifndef _CREATE_SEDP_H
#define _CREATE_SEDP_H

#include <vector>
#include <cstdint>
#include <span>

class symm_encr_data_packet_t
{
  public:
    std::vector<uint8_t> get_encoded() const;

    static symm_encr_data_packet_t create_sedp(std::span<uint8_t> const& data, std::span<uint8_t> session_key);
  private:
    std::vector<uint8_t> m_data, m_session_key;
    symm_encr_data_packet_t();
    
};

#endif /* _CREATE_SEDP_H */
