#ifndef ____GENERIC_PACKET_H
#define ____GENERIC_PACKET_H

#include <vector>
#include <string>
#include <cstdint>
#include <span>
#include <map>
#include <deque>



std::string get_packet_sequence(std::vector<uint8_t> const& encoded_vec);

#endif /* ____GENERIC_PACKET_H */
