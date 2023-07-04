#include <iostream>
#include "blockcipher_blocks.h"
#include "args.hxx"
#include "self-test.h"
#include "except.h"
#include "sedp.h"
#include "file_util.h"
#include "botan/hex.h"
#include "botan/base64.h"
#include "lit_packet.h"

args::Group arguments("arguments");
args::ValueFlag<std::string> input_data_file(arguments, "path", "", {"input-data-file"});
args::ValueFlag<std::string> session_key(arguments, "session_key", "", {"session key"});

namespace cli_args {
const inline std::string input_data_file = "input-data-file";
const inline std::string output_data_file = "output-data-file";
const inline std::string plaintext_data_file = "plaintext-data-file";
const inline std::string session_key = "session-key"; 
}


void ensure_string_arg_is_non_empty(const std::string_view s, const std::string_view argument_name)
{
    if(!s.size())
    {
        throw Exception("missing value for argument " + std::string(argument_name));
    }
}

void run_self_tests_cmd(args::Subparser& /*parser*/)
{

    if (run_self_tests() != 0)
    {
        throw Exception("error during self-test");
    }
}


void create_sedp_cmd(args::Subparser& parser)
{

    args::ValueFlag<std::string> input_data_file_arg(parser, "FILE", cli_args::input_data_file, {'i'});
    args::ValueFlag<std::string> output_data_file_arg(parser, "FILE", cli_args::output_data_file, {'o'});
    args::ValueFlag<std::string> session_key_arg(parser, "HEX", cli_args::session_key, {'k'});
    args::ValueFlag<std::string> plaintext_data_file_arg(parser, "FILE", cli_args::plaintext_data_file, {'p'});
    parser.Parse();
    std::string input_data_file_path = args::get(input_data_file_arg);
    std::string session_key_hex = args::get(session_key_arg);
    std::string output_file_path = args::get(output_data_file_arg);
    std::string plaintext_file_path = args::get(plaintext_data_file_arg);


    ensure_string_arg_is_non_empty(input_data_file_path, cli_args::input_data_file);
    ensure_string_arg_is_non_empty(output_file_path, cli_args::output_data_file);
    ensure_string_arg_is_non_empty(session_key_hex, cli_args::session_key);

    std::cout << "input_data_file path = " << input_data_file_path << std::endl;
    std::cout << "session_key_hex = " << session_key_hex << std::endl;

    auto input_data = read_binary_file(input_data_file_path);

    literal_data_packet_t lit_dat(literal_data_packet_t::format_e::binary, "", 0, input_data);

    auto lit_enc = lit_dat.get_encoded();
    if(plaintext_file_path.size() > 0)
    {
        write_binary_file(std::span(lit_enc), plaintext_file_path);
    }
    auto session_key = Botan::hex_decode(session_key_hex.data(), session_key_hex.data() + session_key_hex.size());
    symm_encr_data_packet_t sedp = symm_encr_data_packet_t::create_sedp(std::span(lit_enc), std::span(session_key));

    auto output_data = sedp.get_encoded();
    
    std::string ascii_armored = Botan::base64_encode(std::span(output_data));
    std::string header_line = "-----BEGIN PGP MESSAGE-----\n\n";
    ascii_armored.insert(ascii_armored.begin(), header_line.begin(), header_line.end());
    std::string _line = "-----BEGIN PGP MESSAGE-----\n\n";

    std::string tail_line = "\n-----END PGP MESSAGE-----\n\n";
    ascii_armored.insert(ascii_armored.end(), tail_line.begin(), tail_line.end());
    write_text_file(ascii_armored, output_file_path);

}

int main(int argc, char* argv[])
{
    args::ArgumentParser p("v5 AEAD CFB-downgrade tool");
    args::Group commands(p, "commands");
    args::CompletionFlag completion(p, {"complete"});
    args::Command create_sedp(commands, "gen-sedp", "generate a symmetrically encrypted data packet, tag 9", &create_sedp_cmd);
    args::Command self_test(commands, "self-test", "run self-tests", &run_self_tests_cmd);
    // args::Group arguments(p, "arguments", args::Group::Validators::DontCare, args::Options::Global);
    try
    {
        p.ParseCLI(argc, argv);


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
    catch (const Exception& e)
    {
        std::cerr << e.what() << std::endl;
        return 1;
    }
    return 0;

    // blockcipher_blocks blocks(16, 3);

    // std::cout << "Hello World!" << std::endl;
    return 0;
}
