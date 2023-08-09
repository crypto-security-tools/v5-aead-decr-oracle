#ifndef FILE_UTIL_H
#define FILE_UTIL_H

#include <vector>
#include <string>
#include <span>
#include <cstdint>
#include <filesystem>

std::vector<uint8_t> read_binary_file (std::string const&  filename);
void write_binary_file(std::span<const uint8_t> data, std::string const& file_path);

void write_text_file(std::string const& data, std::string const& path);

#endif /* FILE_UTIL_H */
