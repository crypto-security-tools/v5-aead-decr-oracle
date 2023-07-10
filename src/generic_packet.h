#ifndef ____GENERIC_PACKET_H
#define ____GENERIC_PACKET_H

#include <vector>
#include <string>
#include <cstdint>
#include <span>
#include <map>



std::string get_packet_sequence (std::span<uint8_t> encoded);

#endif /* ____GENERIC_PACKET_H */
