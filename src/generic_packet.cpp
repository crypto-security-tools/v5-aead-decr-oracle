
#include "generic_packet.h"
#include "packet.h"
#include "except.h"
#include "aead_packet.h"
#include <format>
#include <iostream>


namespace
{
void ensure_min_rem_octets(unsigned nb_required_octets, std::deque<uint8_t> const& d)
{
    if (nb_required_octets > d.size())
    {
        throw Exception("data too short to form a packet");
    }
}
} // namespace


class packet_parse_dump_visitor_t
{
    public:
        packet_parse_dump_visitor_t(std::string & output_string)
            :m_output_str(output_string)
        {
        }

        inline void operator() (uint32_t packet_nb, std::string const& error_str, std::unique_ptr<packet_t> packet_up )
        {
            m_output_str += std::format("[{}] type = {}, body length = {}, errors = {} ", packet_nb, packet::tag2str_map.at(packet_up->raw_tag()), packet_up->body_length(), error_str);
        }
    private:
        std::string m_output_str;
};


static std::vector<uint8_t> read_length_and_consume_content(uint8_t real_packet_tag,
                                                   packet::header_format_e format,
                                                   std::deque<uint8_t>& encoded,
                                                   uint8_t legacy_len_spec,
                                                   bool in_partial_length)
{
    using namespace packet;
    std::vector<uint8_t> result;


    uint64_t packet_length        = 0;
    uint8_t nb_len_octets         = 0;
    bool is_partial_length_header = in_partial_length;
    if (format == header_format_e::new_form)
    {
        if (encoded.size() < 1)
        {
            throw Exception("failed to find new format 1st length octet");
        }
        uint8_t lo_1 = encoded[0];
        encoded.pop_front();
        if (lo_1 < 192)
        {
            nb_len_octets = 1;
            packet_length = lo_1;
            nb_len_octets = 1;
        }
        else if (lo_1 >= 192 && lo_1 <= 223)
        {
            nb_len_octets = 2;
            ensure_min_rem_octets(1, encoded);
            uint8_t lo_2 = encoded[0];
            encoded.pop_front();
            packet_length = ((lo_1 - 192) << 8) + (lo_2) + 192;
        }
        else if (lo_1 == 255)
        {
            nb_len_octets = 5;
            ensure_min_rem_octets(4, encoded);
            uint8_t lo_2  = encoded[0];
            uint8_t lo_3  = encoded[1];
            uint8_t lo_4  = encoded[2];
            uint8_t lo_5  = encoded[3];
            packet_length = (lo_2 << 24) | (lo_3 << 16) | (lo_4 << 8) | lo_5;

            encoded.erase(encoded.begin(), encoded.begin() + 4);
        }
        else // partial body length
        {
            is_partial_length_header = true;
            packet_length            = 1 << (lo_1 & 0x1F);
            nb_len_octets            = 1;
            // the subsequent headers only feature a lenth, not a tag octet: see stream_read_partial_chunk_len() in
            // RNP's stream-packet.cpp .
            // "the last length header in this sequence must not be a partial one" (how can a partial header be the last
            // one? it cannot specify a zero length!)
            bool partial_header_invalid = false;
            if (!(real_packet_tag == static_cast<uint8_t>(tag_e::literal_data) ||
                  real_packet_tag == static_cast<uint8_t>(tag_e::compressed_data) ||
                  real_packet_tag == static_cast<uint8_t>(tag_e::seipd) ||
                  real_packet_tag == static_cast<uint8_t>(tag_e::aead) ||
                  real_packet_tag == static_cast<uint8_t>(tag_e::symm_encr_data)))
            {
                partial_header_invalid = true;
            }

            //result += "|";
            if (partial_header_invalid)
            {
                // write the error but try to continue as this is not fatal
                std::cerr << " ERROR: partial length header not applicable to packet type. " << std::endl;
            }
            std::cerr << std::format(" partial header of length {}\n", packet_length);
        }
    }
    else // old format packet length
    {
        // nb_len_octets   =
        std::cerr << "legacy_len_spec = " << static_cast<unsigned>(legacy_len_spec) << std::endl;
        switch (legacy_len_spec)
        {
            case 0:
            {
                nb_len_octets = 1;
                ensure_min_rem_octets(nb_len_octets, encoded);
                packet_length = encoded[0];
                encoded.pop_front();
                break;
            }
            case 1:
            {
                nb_len_octets = 2;
                ensure_min_rem_octets(nb_len_octets, encoded);
                std::cerr << "2 len octets = " << static_cast<unsigned>(encoded[0]) << ", "
                          << static_cast<unsigned>(encoded[1]) << std::endl;
                packet_length = encoded[0] << 8 | encoded[1];
                encoded.erase(encoded.begin(), encoded.begin() + 2);
                break;
            }
            case 2:
            {
                nb_len_octets = 4;
                ensure_min_rem_octets(nb_len_octets, encoded);
                packet_length = encoded[0] << 24 | encoded[1] << 16 | encoded[2] << 8 | encoded[3];
                encoded.erase(encoded.begin(), encoded.begin() + 4);
                break;
            }
            case 3:
            {
                nb_len_octets = 0;
                // assume the packet takes up the whole file
                packet_length = encoded.size();
                break;
            }
        };
    }
    std::cerr << "packet length = " << packet_length << std::endl;
    //std::string packet_details;
    if (encoded.size() >= packet_length)
    {
        result.insert(result.end(), encoded.begin(), encoded.begin() + packet_length);
        encoded.erase(encoded.begin(), encoded.begin() + packet_length);
    }
    else
    {
        // need to abort here
        throw Exception(" error: packet body length larger than remaining data");
        return result;
    }
    if (is_partial_length_header && packet_length > 0)
    {
        // the partial length portion of this partial header was consumed above already.
        // if we are in a partial length header, we recurse here to find the further portions
        auto new_part = read_length_and_consume_content(
            real_packet_tag, format, encoded, legacy_len_spec, is_partial_length_header);
        result.insert(result.end(), new_part.begin(), new_part.end()); 
        return result;
    }
    // encoded.erase(encoded.begin(), encoded.begin() + packet_length);
    //result += std::format(" body length: {}", packet_length);
    //result += "\n" + packet_details;
    return result;
}

packet_sequence_t get_packet_sequence(std::vector<uint8_t> const& encoded_vec)
{
    packet_sequence_t result;
    std::deque<uint8_t> encoded;
    encoded.assign(encoded_vec.begin(), encoded_vec.end());
    std::string error_str;
    while (encoded.size())
    {
        using namespace packet;
        //result += " | ";
        uint8_t encoded_tag = encoded[0];
        encoded.pop_front();
        uint8_t real_packet_tag = 0;
        bool is_indet_len       = false;
        uint8_t legacy_len_spec = 0;
        if (!(encoded_tag & 0x80))
        {
            // can continue here
            error_str += " (invalid bit 7 in packet tag!)";
        }

        header_format_e format = header_format_e::legacy;

        if (encoded_tag & 0x40) // bit 6 (counting bits as 7 ... 0)
        {
            format          = header_format_e::new_form;
            real_packet_tag = encoded_tag & ~(0xc0);
            //std::cerr << "new format header" << std::endl;
        }
        else
        {
            real_packet_tag = (encoded_tag >> 2) & 0x0F;
            legacy_len_spec = encoded_tag & 0x03;
            //std::cerr << "old format header" << std::endl;
        }
        if (!is_valid_packet_tag(real_packet_tag))
        {
            std::cerr << std::format(" encountered invalid packet tag {} (fatal).\n", real_packet_tag);
            return result; 
        }
        auto body = read_length_and_consume_content(real_packet_tag, format, encoded, legacy_len_spec, false);
        std::unique_ptr<packet_t> new_packet = create_packet(static_cast<packet::tag_e>(real_packet_tag), format, body);
       result.push_back(std::move(new_packet)); 
    }
    return result;
}
