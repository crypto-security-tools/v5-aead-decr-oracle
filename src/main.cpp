#include <iostream>
#include <format>
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

namespace cli_args
{
const inline std::string input_data_file     = "input-data-file";
const inline std::string output_data_file    = "output-data-file";
const inline std::string plaintext_data_file = "plaintext-data-file";
const inline std::string session_key         = "session-key";
const inline std::string reused_pkesk        = "reused-pkesk";
const inline std::string invalid_quick_check = "invalid-quick-check";
} // namespace cli_args


void ensure_string_arg_is_non_empty(const std::string_view s, const std::string_view argument_name)
{
    if (!s.size())
    {
        throw cli_exception_t("missing value for argument " + std::string(argument_name));
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

    args::ValueFlag<std::string> input_data_file_arg(
        parser, "FILE", "path to file with data to encrypt", {'i', cli_args::input_data_file});
    args::ValueFlag<std::string> output_data_file_arg(
        parser, "FILE", "path to the encrypted file to be generated", {'o', cli_args::output_data_file});
    args::ValueFlag<std::string> session_key_arg(
        parser, "HEX", "the session key for the generated SED", {'k', cli_args::session_key});
    args::ValueFlag<std::string> plaintext_data_file_arg(
        parser,
        "FILE",
        "optional: path to an output file which receives the data that is encrypted (including the surrounding packet",
        {'p', cli_args::plaintext_data_file});
    args::ValueFlag<std::string> reused_pkesk_arg(
        parser,
        "FILE",
        "optional: path to a PGP message file starting with a PKESK packet, which will be extracted and prepended to "
        "the generated SED packet. The PKESK must be in raw binary format, not ASCII-armored.",
        {'u', cli_args::reused_pkesk});
    args::Flag invalid_quick_check_arg(parser,
                                       "invalid-quick-check",
                                       "if set then a SED packet with invalid quick-check bytes will be created",
                                       {
                                           'q',
                                           cli_args::invalid_quick_check,
                                       });
    parser.Parse();
    std::string input_data_file_path = args::get(input_data_file_arg);
    std::string session_key_hex      = args::get(session_key_arg);
    std::string output_file_path     = args::get(output_data_file_arg);
    std::string plaintext_file_path  = args::get(plaintext_data_file_arg);
    std::string reused_pkesk_path    = args::get(reused_pkesk_arg);
    bool invalid_quick_check         = args::get(invalid_quick_check_arg);


    ensure_string_arg_is_non_empty(input_data_file_path, cli_args::input_data_file);
    ensure_string_arg_is_non_empty(output_file_path, cli_args::output_data_file);
    ensure_string_arg_is_non_empty(session_key_hex, cli_args::session_key);

    std::cout << "input_data_file path = " << input_data_file_path << std::endl;
    std::cout << "session_key_hex = " << session_key_hex << std::endl;
    std::cout << std::format("invalid quick-check: {}", invalid_quick_check) << std::endl;

    auto input_data = read_binary_file(input_data_file_path);

    literal_data_packet_t lit_dat(literal_data_packet_t::format_e::binary, "", 0, input_data);

    auto lit_enc = lit_dat.get_encoded();
    if (plaintext_file_path.size() > 0)
    {
        write_binary_file(std::span(lit_enc), plaintext_file_path);
    }

    using enum symm_encr_data_packet_t::quick_check_spec_e;

    auto session_key = Botan::hex_decode(session_key_hex.data(), session_key_hex.data() + session_key_hex.size());
    symm_encr_data_packet_t sedp = symm_encr_data_packet_t::create_sedp(
        std::span(lit_enc), std::span(session_key), invalid_quick_check ? invalid : valid);

    auto output_data = sedp.get_encoded();


    if (reused_pkesk_path.size() > 0)
    {
        auto pkesk = read_binary_file(reused_pkesk_path);
        pkesk.insert(pkesk.end(), output_data.begin(), output_data.end());
        write_binary_file(std::span(pkesk), output_file_path);
    }
    else
    {
        // in this case write ascii-armored (no specific reason for this, but documents how that works)
        std::string ascii_armored = Botan::base64_encode(std::span(output_data));
        std::string header_line   = "-----BEGIN PGP MESSAGE-----\n\n";
        ascii_armored.insert(ascii_armored.begin(), header_line.begin(), header_line.end());
        std::string _line = "-----BEGIN PGP MESSAGE-----\n\n";

        std::string tail_line = "\n-----END PGP MESSAGE-----\n\n";
        ascii_armored.insert(ascii_armored.end(), tail_line.begin(), tail_line.end());
        write_text_file(ascii_armored, output_file_path);
    }
}

int main(int argc, char* argv[])
{
    args::ArgumentParser p("v5 AEAD CFB-downgrade tool");
    args::Group commands(p, "commands");
    args::CompletionFlag completion(p, {"complete"});
    args::Command create_sedp(
        commands, "gen-sedp", "generate a symmetrically encrypted data packet, tag 9", &create_sedp_cmd);
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
    catch (const cli_exception_t& e)
    {
        std::cerr << p << std::endl << e.what() << std::endl;
        return 1;
    }
    catch (const Exception& e)
    {
        std::cerr << e.what() << std::endl;
        return 1;
    }
    return 0;
}
