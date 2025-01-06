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

class file_exception_t : public Exception 
{
  public:
    file_exception_t(const char* prefix, const std::string& msg);
    explicit file_exception_t(const std::string& msg);
    virtual ~file_exception_t();

  protected:
    file_exception_t(const std::string& msg, const std::exception& e);

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

class test_exception_t : public Exception 
{
  public:
    test_exception_t(const char* prefix, const std::string& msg);
    explicit test_exception_t(const std::string& msg);
    virtual ~test_exception_t();

  protected:
    test_exception_t(const std::string& msg, const std::exception& e);

};


class attack_exception_t : public Exception 
{
  public:
    attack_exception_t(const char* prefix, const std::string& msg);
    explicit attack_exception_t(const std::string& msg);
    virtual ~attack_exception_t();

  protected:
    attack_exception_t(const std::string& msg, const std::exception& e);

};

#endif /* _EXCEPT_H */
