
#include "bit_string.h"
#include "except.h"

namespace
{

void padd_with_leading_zeros(bit_string_t& bs, std::size_t to_length)
{
    std::size_t to_add = to_length - bs.size();
    if (to_add > to_length)
    {
        throw Exception("cannot pad to smaller length");
    }
    for (std::size_t i = 0; i < to_add; i++)
    {
        bs.insert(bs.begin(), 0);
    }
}
} // namespace

bit_string_t& bit_string_t::operator^=(const bit_string_t& rhs)
{
    bit_string_t* padded_lhs       = this;
    const bit_string_t* padded_rhs = &rhs;
    bit_string_t working_copy(this->size()); // will be reasisgned in any case
    if (padded_lhs->size() > padded_rhs->size())
    {
        working_copy = rhs;
        padd_with_leading_zeros(working_copy, padded_lhs->size());
    }
    else if (padded_lhs->size() < padded_rhs->size())
    {
        working_copy = *this;
        padd_with_leading_zeros(working_copy, padded_rhs->size());
    }
    if (padded_lhs->size() != padded_rhs->size())
    {
        throw Exception("internal error: lengths in XOR don't match");
    }
    for (size_t i = 0; i < padded_rhs->size(); i++)
    {
        (*padded_lhs)[i] ^= (*padded_rhs)[i];
    }
    *this = *padded_lhs;
    return *this;
}
