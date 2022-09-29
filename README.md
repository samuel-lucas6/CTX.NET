[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/samuel-lucas6/CTXConstruction/blob/main/LICENSE)

# CTXConstruction

Chan and Rogaway's [fully committing AEAD scheme](https://eprint.iacr.org/2022/1260.pdf) using ChaCha20-Poly1305 and BLAKE2b-160.

> **Warning**
> 
> I do **NOT** recommend using this. This was done quickly and may be a misinterpretation. Reading the paper quickly is confusing since the tag being hashed is calculated over the plaintext, not the ciphertext. If correct, this means you can't easily convert an AEAD into a fully committing AEAD scheme because one is Encrypt-then-MAC, the other Encrypt-and-MAC.
