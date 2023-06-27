
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
