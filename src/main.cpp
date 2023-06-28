#include <iostream>
#include "blockcipher_blocks.h"
#include "args.hxx"
#include "self-test.h"

int main(int argc, char* argv[])
{
    args::ArgumentParser p("v5 AEAD CFB-downgrade tool");
    args::CompletionFlag completion(p, {"complete"});
    args::Group commands(p, "commands");
    args::Command self_test(commands, "self-test", "run self-tests");
    try
    {
        p.ParseCLI(argc, argv);
        if (self_test)
        {
           return run_self_tests(); 
        }


        std::cout << std::endl;
    }
    catch (const args::Completion& e)
    {
        std::cout << e.what();
        return 0;
    }
    catch (args::Help)
    {
        std::cout << p;
    }
    catch (args::ValidationError e)
    {
        std::cerr << e.what() << std::endl;
        std::cerr << p;
        return 1;
    }
    catch (const args::ParseError& e)
    {
        std::cerr << e.what() << std::endl;
        std::cerr << p;
        return 1;
    }
    catch (const args::Error& e)
    {
        std::cerr << e.what() << std::endl << p;
        return 1;
    }
    return 0;

    //blockcipher_blocks blocks(16, 3);

    //std::cout << "Hello World!" << std::endl;
    return 0;
}
