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

#endif /* _EXCEPT_H */
