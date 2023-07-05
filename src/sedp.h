#ifndef _CREATE_SEDP_H
#define _CREATE_SEDP_H

#include <vector>
#include <cstdint>
#include <span>
#include "packet.h"

class symm_encr_data_packet_t : public packet_t
{
  public:
    enum class quick_check_spec_e
    {
        valid,
        invalid
    };

    static symm_encr_data_packet_t create_sedp_from_plaintext(std::span<const uint8_t> data,
                                               std::span<const uint8_t> session_key,
                                               quick_check_spec_e quick_check = quick_check_spec_e::valid);

    static symm_encr_data_packet_t create_sedp_from_ciphertext(std::span<const uint8_t> ciphertext);

    std::vector<uint8_t> packet_contents() const override final;

  private:

    static std::vector<uint8_t> aes_sedp_encrypt_payload(std::span<const uint8_t> session_key, std::span<const uint8_t> plaintext, quick_check_spec_e quick_check_validity);
    std::vector<uint8_t> m_ciphertext, m_session_key;
    quick_check_spec_e m_quick_check = quick_check_spec_e::valid;
    symm_encr_data_packet_t();
};

#endif /* _CREATE_SEDP_H */
