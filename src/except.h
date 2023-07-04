#ifndef _EXCEPT_H
#define _EXCEPT_H

#include <string>
#include <exception>

class Exception : public std::exception
{
  public:
    Exception(const char* prefix, const std::string& msg);
    explicit Exception(const std::string& msg);
    const char* what() const noexcept override
    {
        return m_msg.c_str();
    }
    virtual ~Exception();

  protected:
    Exception(const std::string& msg, const std::exception& e);

  private:
    std::string m_msg;
};


class cli_exception_t : public Exception 
{
  public:
    cli_exception_t(const char* prefix, const std::string& msg);
    explicit cli_exception_t(const std::string& msg);
    virtual ~cli_exception_t();

  protected:
    cli_exception_t(const std::string& msg, const std::exception& e);

};

#endif /* _EXCEPT_H */
