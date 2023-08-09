
#include "file_util.h"
#include <fstream>
#include <istream>
#include "except.h"

using namespace std;


std::vector<uint8_t> read_binary_file(std::string const& filename)
{
    long size;
    std::vector<uint8_t> result;
    std::ifstream file(filename, ios::in | ios::binary | ios::ate);
    if (file.fail())
    {
        throw file_exception_t("could not open file for reading at " + filename);
    }

    size = file.tellg();
    file.seekg(0, ios::beg);
    result.resize(size);
    file.read(reinterpret_cast<char*>(result.data()), size);
    file.close();
    return result;
}


void write_binary_file(std::span<const uint8_t> data, std::string const& file_path)
{
    auto myfile = std::fstream(file_path, std::ios::out | std::ios::binary);
    if (myfile.fail())
    {
        throw Exception("could not open file for writing at " + file_path);
    }

    myfile.write((char*)&data[0], data.size());
    myfile.close();
}

void write_text_file(std::string const& data, std::string const& path)
{
    ofstream fw(path, std::ofstream::out);
    // check if file was successfully opened for writing
    if (fw.is_open())
    {
        fw << data;
        fw.close();
    }
    else
    {
        throw Exception("could not open file for writing: " + std::string(path));
    }
}
