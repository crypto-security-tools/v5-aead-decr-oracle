
#include "generic_packet.h"
#include "except.h"

namespace
{
void ensure_packet_header_fits(unsigned nb_required_len_octets, uint64_t encoded_total_size)
{
    if (nb_required_len_octets > 1 + encoded_total_size)
    {
        throw Exception("data too short to form a packet");
    }
}
} // namespace

// use std::dequeue
// separate out length parsing (for indet. len headers)
// each parsing function removes consumed data from the beginning.

std::string get_packet_sequence (std::span<uint8_t> encoded)
{
    if (encoded.size() < 1)
    {
        throw Exception("data too short to form a packet");
    }
    uint8_t encoded_tag     = encoded[0];
    uint8_t real_packet_tag = 0;
    bool is_indet_len = false;
    if (!(encoded_tag & 0x80))
    {
        throw(Exception("invalid bit 7 in packet tag"));
    }
    bool new_format = false;
    if (encoded_tag & 0x40) // bit 6 (counting bits as 7 ... 0)
    {
        new_format = true;
    }
    uint8_t lo_1           = encoded[1];
    uint64_t packet_length = 0;
    uint8_t nb_len_octets  = 0;
    if (new_format)
    {
        real_packet_tag = encoded_tag & ~(0xc0);
        if (lo_1 < 192)
        {
            nb_len_octets = 1;
            ensure_packet_header_fits(nb_len_octets, encoded.size());
            packet_length = lo_1;
            nb_len_octets = 1;
        }
        else if (lo_1 >= 192 && lo_1 <= 223)
        {
            nb_len_octets = 2;
            ensure_packet_header_fits(nb_len_octets, encoded.size());
            uint8_t lo_2  = encoded[2];
            packet_length = ((lo_1 - 192) << 8) + (lo_2) + 192;
        }
        else if (lo_1 == 255)
        {
            nb_len_octets = 5;
            ensure_packet_header_fits(nb_len_octets, encoded.size());
            uint8_t lo_2 = encoded[2];
            uint8_t lo_3 = encoded[3];
            uint8_t lo_4 = encoded[4];
            uint8_t lo_5 = encoded[5];

            packet_length = (lo_2 << 24) | (lo_3 << 16) | (lo_4 << 8) | lo_5;
        }
        else // partial body length
        {
            packet_length = 1 << (lo_1 & 0x1F);
            nb_len_octets = 1;
            // the subsequent headers only feature a lenth, not a tag octet
            // the last length header in this sequence must not be a partial one
            // TODO: SPECIAL HANDLING NEEDED, must recurse
        }
    }
    else // old format packet length
    {
        real_packet_tag = (encoded_tag >> 2) & 0x0F;
        // nb_len_octets   = encoded_tag & 0x03;
        switch (nb_len_octets)
        {
            case 0:
            {
                nb_len_octets = 1;
                ensure_packet_header_fits(nb_len_octets, encoded.size());
                packet_length = encoded[1];
                break;
            }
            case 1:
            {
                nb_len_octets = 2;
                ensure_packet_header_fits(nb_len_octets, encoded.size());
                packet_length = encoded[1] << 8 | encoded[2]; // BE encoding correct?
                break;
            }
            case 2:
            {
                nb_len_octets = 5;
                ensure_packet_header_fits(nb_len_octets, encoded.size());
                packet_length = encoded[1] << 24 | encoded[2] << 16 | encoded[3] << 8 | encoded[4];
                break;
            }
            case 3:
            {
                nb_len_octets = 0;
                // assume the packet takes up the whole file
                packet_length = encoded.size() - 1;
                break;
            }
        };
    }

}
