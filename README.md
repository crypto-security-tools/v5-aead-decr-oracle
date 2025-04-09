
# Test tool for LibrePGP v5 AEAD-to-CFB downgrade attacks

This tool implements the AEAD-to-CFB (more specifically OCB-to-CFB) downgrade attack described in https://eprint.iacr.org/2024/1110 as a proof of concept.

## Building the tool

The tool only runs under Unix OS. It has been tested on Debian 10, but should run on any newer distribution as well. It requires GCC 13.1 or higher.

The following prerequisites have to be installed and the corresponding CMake variables of `v5-aead-decr-oracle` be set:

| Library        | GitHub URL                                      | Commit known to work                     | CMake variables to set                                                                        |
| ---            | --                                              | -----                                    | ---                                                                                           |
| Botan 3        | https://github.com/randombit/botan              | 3bee7a12a750c50a90d8147fa2d38c707b032592 | BOTAN_INCLUDE_DIR: set to `.../botan/build/include/public`, BOTAN_LIB_DIR: set to `.../botan` |
| args           | https://github.com/Taywee/args                  | b7d67237e8bdaa517d7fd6e4e84e1f6efa24f8c5 | TARGS_INCLUDE_DIR: set to `.../args`                                                          |
| cpp-subprocess | https://github.com/arun11299/cpp-subprocess.git | af23f338801ed19696da42b1f9b97f8e21dec5d6 | CPP_SUBPROCESS_INCLUDE_DIR: set to `.../cpp-subprocess`                                       |

Afterwards the tool can be built with CMake.

The GnuPG command line application must be available in the PATH variable. The attack code uses the GnuPG to perform the SED packet trial encryptions. The attack application invokes it by issuing the command `gpg`.  This version does not need to support LibrePGP OCB packets.

For the purpose of verifying the decryption of the initial unmodified packet and the one produced by the attack, however, it must be ensured that a version of GnuPG is used that supports the LibrePGP OCB packets.


## Sample attack

This section describes how to execute a sample attack against a combination of a PKESK and OCB packet that is contained in the repository together with the corresponding OpenPGP private key. The attack uses an SED-decryption oracle to replace one chunk in the OCB ciphertext with whitespaces.


### Import the test key

Before importing the test private key, consider creating a distinct key ring for it.
If it is imported into a key ring that already contains other keys, then during the attack, which performs numerous trial decryptions of manipulated ciphertexts, there will occur prompts for password entry.
This can be avoided by importing the key to a keyring of a user that has no other keys. The attack tool does not support the choice of a custom key ring. Accordingly, it is recommended to run it under a Unix user that has not other keys.

Change into the CMake build directory and execute the command
```
gpg --import ../artifacts/test-key.asc
```

### Decrypt the original plaintext
Change into the CMake build directory and execute the command
```
gpg --decrypt --show-session-key  ../artifacts/doc.aead.ocb.small-chunks-with-key-FFE671A89D964808EB47EB2D956EEF7B8EF5660D9425750ECC94038C8E7AC914-no-compression.gpg.bin
```
The expected output is

    gpg: encrypted with 3072-bit RSA key, ID D6B5C6B229E30C28, created 2023-06-28
          "test key <test@example.com>"
    gpg: session key: '9:FFE671A89D964808EB47EB2D956EEF7B8EF5660D9425750ECC94038C8E7AC914'
    ```
    KMAC256(K, X, L, S):
    Validity Conditions: len(K) < 2²⁰⁴⁰ and 0 ≤ L < 2²⁰⁴⁰ and len(S) < 2²⁰⁴⁰

    1. newX = bytepad(encode_string(K), 136) || X || right_encode(L).
    2. T = bytepad(encode_string(“KMAC”) || encode_string(S), 136).
    3. return KECCAK[512](T || newX || 00, L)  // "00" is the 2-bit padding
    ```

### Run the attack to produce a manipulated ciphertext


Change into the CMake build directory and execute the command
```
./v5-aead-attack replace-chunk -u ../artifacts/doc.aead.ocb.small-chunks-with-key-FFE671A89D964808EB47EB2D956EEF7B8EF5660D9425750ECC94038C8E7AC914-no-compression.pkesk.bin --iterations=100 --data-log-dir=run_time -kFFE671A89D964808EB47EB2D956EEF7B8EF5660D9425750ECC94038C8E7AC914 --nb-leading-random-bytes=256  --query-repeat-count=100 --file-with-aead-packet ../artifacts/doc.aead.ocb.small-chunks-with-key-FFE671A89D964808EB47EB2D956EEF7B8EF5660D9425750ECC94038C8E7AC914-no-compression.gpg.bin
```
Here, the specification of the session key with `-kFFE671A89D964808EB47EB2D956EEF7B8EF5660D9425750ECC94038C8E7AC914` that was determined in the previous step is optional.
It is used to detect some rare errors that can lead to a false detection of a repeated pattern in the decryption result that will lead to failure of the attack. Remove this argument to execute the attack under realistic conditions.

You will see a lot of output and possibly password entry requests in case you have password protected keys in the key ring that is used. 

List the latest sub directory of `run_time` (under the CMake build folder). If the attack was successful, then it contains at least one file ending in `pkesk-then-aead-packet-with-final-chunk-replaced`

### Run decrypt the manipulated AEAD ciphertext
Change into the cmake build directory and execute the command (replacing the time stamp with the one of the latest run from the previous step and choosing one file ending in `pkesk-then-aead-packet-with-final-chunk-replaced`, should there
be multiple)
```
gpg --decrypt run_time/2025-03-25--10-18-00/74-pkesk-then-aead-packet-with-final-chunk-replaced
```

The expected output is

    gpg: encrypted with 3072-bit RSA key, ID D6B5C6B229E30C28, created 2023-06-28
          "test key <test@example.com>"
    gpg: session key: '9:FFE671A89D964808EB47EB2D956EEF7B8EF5660D9425750ECC94038C8E7AC914'
    ```
    KMAC256(K, X, L, S):
    Validity Conditions: len(K) < 2²⁰⁴⁰ and 0 ≤ L < 2²⁰⁴⁰ and len(S) < 2²⁰⁴⁰

    1. newX = bytepad(encode_string(K), 136) || X || right_encode(L).
    2. T = bytepad(encode_string(“KMAC”) || encode_st                                                                " is the 2-bit padding
    ```

The content of the next-to-final chunk has been replaced with whitespaces.

# License

If not otherwise noted in the source code files, they are under Apache License v2 (see file `LICENSE`). The files adopted from Botan are under the Botan license (see file `botan_license.txt`).
