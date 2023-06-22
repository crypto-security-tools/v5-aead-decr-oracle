#include "stdint.h"
#include <vector>

void store_be64(uint8_t out[4], uint64_t in);

std::vector<uint8_t> compute_eax_nonce(std::vector<uint8_t> iv, std::vector<uint8_t> chunk_idx) ;