#ifndef ____UTIL_H
#define ____UTIL_H

#include <string>
#include <filesystem>
#include <span>
#include "except.h"
#include "file_util.h"

class run_time_ctrl_t

{
  public:
    run_time_ctrl_t(std::filesystem::path const& run_time_log_dir = "") 
    {
        auto t  = std::time(nullptr);
        auto tm = *std::localtime(&t);
        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%d--%H-%M-%S");
        auto date_str = oss.str();
        m_run_time_log_dir = run_time_log_dir / std::filesystem::path(date_str);
        std::filesystem::create_directories(m_run_time_log_dir);
    }

    void potentially_write_run_time_file(std::span<uint8_t> data, std::string const& leaf_name)
    {
        if (m_run_time_log_dir == "")
        {
            return;
        }
        if (leaf_name == "")
        {
            throw Exception("attempt to write file without leaf name");
        }
        auto file_path = m_run_time_log_dir / leaf_name;
        if (std::filesystem::exists(file_path))
        {
            throw Exception(std::string("file path ") + file_path.c_str() + " already exists");
        }
        write_binary_file(data, file_path);
    }

  private:
    std::filesystem::path m_run_time_log_dir;
};


std::string botan_aes_cfb_cipher_spec_from_key_byte_len(unsigned key_byte_len);


void lenght_is_multiple_of_aes_block_size_or_throw(std::span<const uint8_t> x);

#endif /* ____UTIL_H */
