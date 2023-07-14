# SED with Oracle Query

* `longer-sed-lit.bin` – original SED packet containing a proper LIT packet in the plaintext
  * 7d9105a37c6ed176115829d61a8e135e86ffdf4d70835ff881d17dca56f67998 is the AES session key fitting to that packet
* `test-key.asc` – the OpenPGP test key fitting to the used PKESK
* `sed-lit-query.bin` – modification of `longer-sed-lit` with a single block query that is placed with at the offset of two blocks into the 2nd step ciphertext of the OpenPGP CFB ciphertext
* `pkesk-sed-query.bin` – `sed-lit-query.bin` with a prepended fitting to the session key and with the test-key as recipient
* `sed-lit-query_decrypted.bin` – The decryption result of `pkesk-sed-query.bin`. The repeated block pattern is obvious from the plaintext.
* 
