#include <vector>
#include "stdint.h"

class blockcipher_blocks
{
public:
    blockcipher_blocks(unsigned block_size, unsigned num_blocks);
    
private:
    unsigned block_size;
    std::vector<uint8_t> blocks;
};