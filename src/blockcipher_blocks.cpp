#include "blockcipher_blocks.h"

blockcipher_blocks::blockcipher_blocks(unsigned block_size, unsigned num_blocks)
{
    blocks = std::vector<uint8_t>(num_blocks);
}