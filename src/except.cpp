
#include "except.h"

Exception::~Exception() {};

Exception::Exception(const std::string& msg) : m_msg(msg)
{
}

Exception::Exception(const std::string& msg, const std::exception& e)
    : m_msg(msg + " failed with " + std::string(e.what()))
{
}

Exception::Exception(const char* prefix, const std::string& msg) : m_msg(std::string(prefix) + " " + msg)
{
}

file_exception_t::~file_exception_t() {};

file_exception_t::file_exception_t(const std::string& msg) : Exception(msg)
{
}

file_exception_t::file_exception_t(const std::string& msg, const std::exception& e)
    : Exception(msg + " failed with " + std::string(e.what()))
{
}

file_exception_t::file_exception_t(const char* prefix, const std::string& msg)
    : Exception(std::string(prefix) + " " + msg)
{
}

cli_exception_t::~cli_exception_t() {};

cli_exception_t::cli_exception_t(const std::string& msg) : Exception(msg)
{
}

cli_exception_t::cli_exception_t(const std::string& msg, const std::exception& e)
    : Exception(msg + " failed with " + std::string(e.what()))
{
}

cli_exception_t::cli_exception_t(const char* prefix, const std::string& msg)
    : Exception(std::string(prefix) + " " + msg)
{
}


test_exception_t::~test_exception_t() {};

test_exception_t::test_exception_t(const std::string& msg) : Exception(msg)
{
}

test_exception_t::test_exception_t(const std::string& msg, const std::exception& e)
    : Exception(msg + " failed with " + std::string(e.what()))
{
}

test_exception_t::test_exception_t(const char* prefix, const std::string& msg)
    : Exception(std::string(prefix) + " " + msg)
{
}
