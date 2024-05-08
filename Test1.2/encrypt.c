#include "api.h"
#include "ascon.h"
#include "crypto_aead.h"
#include "permutations.h"
#include "printstate.h"
#include "word.h"

#include <stdio.h> // Include for print_hex function
#include <time.h>  // Include for calculate_memory_consumption function

void print_hex(const unsigned char* data, unsigned long long len) {
    unsigned long long i;
    for (i = 0; i < len; ++i) {
        printf("%02X ", data[i]);
    }
}

int calculate_avalanche_effect(const unsigned char* m, unsigned long long mlen,
                                const unsigned char* ad, unsigned long long adlen,
                                const unsigned char* npub, const unsigned char* k) {
    unsigned char c[512]; // Assuming a maximum ciphertext length of 512 bytes
    unsigned long long clen;
    unsigned char m_copy[256]; // Copy of the plaintext for modification
    unsigned char k_copy[32]; // Copy of the key for modification

    // Copy the original plaintext and key
    memcpy(m_copy, m, mlen);
    memcpy(k_copy, k, 32);

    // Variables to store avalanche effect percentages
    double plaintext_avalanche = 0.0;
    double key_avalanche = 0.0;

    // Perform encryption with original inputs
    crypto_aead_encrypt(c, &clen, m, mlen, ad, adlen, NULL, npub, k);

    // Modify each bit of the plaintext and calculate avalanche effect
    unsigned long long i;
    for (i = 0; i < mlen; ++i) {
        // Modify a single bit in the plaintext copy
        m_copy[i] ^= 0x01;

        // Encrypt the modified plaintext
        crypto_aead_encrypt(c, &clen, m_copy, mlen, ad, adlen, NULL, npub, k);

        // Calculate the percentage of bits that changed
        unsigned long long bit_changes = 0;
        unsigned long long j;
        for ( j = 0; j < clen; ++j) {
            unsigned char diff = c[j] ^ c[j - mlen]; // Compare corresponding bytes
            unsigned long long k ;
            for (k= 0; k < 8; ++k) {
                if ((diff >> k) & 0x01) {
                    bit_changes++;
                }
            }
        }

        // Calculate and accumulate avalanche effect for plaintext bits
        plaintext_avalanche += (double)bit_changes / (clen * 8) * 100.0;

        // Restore the modified plaintext for the next iteration
        m_copy[i] ^= 0x01;
    }

    // Modify each bit of the key and calculate avalanche effect
    for (i = 0; i < 32; ++i) {
        // Modify a single bit in the key copy
        k_copy[i] ^= 0x01;

        // Encrypt the plaintext with the modified key
        crypto_aead_encrypt(c, &clen, m, mlen, ad, adlen, NULL, npub, k_copy);

        // Calculate the percentage of bits that changed
        unsigned long long bit_changes = 0;
        unsigned long long j;
        for ( j = 0; j < clen; ++j) {
            unsigned char diff = c[j] ^ c[j - mlen]; // Compare corresponding bytes
            unsigned long long k;
            for ( k = 0; k < 8; ++k) {
                if ((diff >> k) & 0x01) {
                    bit_changes++;
                }
            }
        }

        // Calculate and accumulate avalanche effect for key bits
        key_avalanche += (double)bit_changes / (clen * 8) * 100.0;

        // Restore the modified key for the next iteration
        k_copy[i] ^= 0x01;
    }

    // Calculate average avalanche effect percentages
    plaintext_avalanche /= mlen;
    key_avalanche /= 32;

    // Print the avalanche effect percentages
    printf("Avalanche Effect for Plaintext Bits: %.2f%%\n", plaintext_avalanche);
    printf("Avalanche Effect for Key Bits: %.2f%%\n", key_avalanche);
    return plaintext_avalanche;
}

void calculate_memory_consumption() {
    printf("Memory Consumption:\n");

    printf("Size of state_t structure: %zu bytes\n", sizeof(state_t));
    printf("Size of uint64_t: %zu bytes\n", sizeof(uint64_t));
    printf("Size of ASCON_128_IV constant: %zu bytes\n", sizeof(ASCON_128_IV));
    printf("Size of ASCON_128_RATE constant: %zu bytes\n", sizeof(ASCON_128_RATE));
    printf("Size of PAD() function: %zu bytes\n", sizeof(PAD(0))); // Assuming PAD() returns a constant

    // Calculate the total memory consumption based on the sizes of individual components
    size_t total_memory = sizeof(state_t) + 2 * sizeof(uint64_t) + 2 * sizeof(ASCON_128_IV) +
                          sizeof(ASCON_128_RATE) + sizeof(PAD(0));
    printf("Total Memory Consumption in encryption algorithm: %zu bytes\n", total_memory);
}

int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
                        const unsigned char* m, unsigned long long mlen,
                        const unsigned char* ad, unsigned long long adlen,
                        const unsigned char* nsec, const unsigned char* npub,
                        const unsigned char* k) {
  (void)nsec;

  /* set ciphertext size */
  *clen = mlen + CRYPTO_ABYTES;

  /* load key and nonce */
  const uint64_t K0 = LOADBYTES(k, 8);
  const uint64_t K1 = LOADBYTES(k + 8, 8);
  const uint64_t N0 = LOADBYTES(npub, 8);
  const uint64_t N1 = LOADBYTES(npub + 8, 8);

  /* initialize */
  state_t s;
  s.x0 = ASCON_80PQ_IV;
  s.x1 = K0;
  s.x2 = K1;
  s.x3 = N0;
  s.x4 = N1;
  P12(&s);
  s.x3 ^= K0;
  s.x4 ^= K1;
  printstate("initialization", &s);

  if (adlen) {
    /* full associated data blocks */
    while (adlen >= ASCON_128_RATE) {
      s.x0 ^= LOADBYTES(ad, 8);
      P6(&s);
      ad += ASCON_128_RATE;
      adlen -= ASCON_128_RATE;
    }
    /* final associated data block */
    s.x0 ^= LOADBYTES(ad, adlen);
    s.x0 ^= PAD(adlen);
    P6(&s);
  }
  /* domain separation */
  s.x4 ^= 1;
  printstate("process associated data", &s);

  /* full plaintext blocks */
  while (mlen >= ASCON_128_RATE) {
    s.x0 ^= LOADBYTES(m, 8);
    STOREBYTES(c, s.x0, 8);
    P6(&s);
    m += ASCON_128_RATE;
    c += ASCON_128_RATE;
    mlen -= ASCON_128_RATE;
  }
  /* final plaintext block */
  s.x0 ^= LOADBYTES(m, mlen);
  STOREBYTES(c, s.x0, mlen);
  s.x0 ^= PAD(mlen);
  c += mlen;
  printstate("process plaintext", &s);

  /* finalize */
  s.x1 ^= K0;
  s.x2 ^= K1;
  P12(&s);
  s.x3 ^= K0;
  s.x4 ^= K1;
  printstate("finalization", &s);

  /* set tag */
  STOREBYTES(c, s.x3, 8);
  STOREBYTES(c + 8, s.x4, 8);

  return 0;
}

int crypto_aead_decrypt(unsigned char* m, unsigned long long* mlen,
                        unsigned char* nsec, const unsigned char* c,
                        unsigned long long clen, const unsigned char* ad,
                        unsigned long long adlen, const unsigned char* npub,
                        const unsigned char* k) {
  (void)nsec;

  if (clen < CRYPTO_ABYTES) return -1;

  /* set plaintext size */
  *mlen = clen - CRYPTO_ABYTES;

  /* load key and nonce */
  const uint64_t K0 = LOADBYTES(k, 8);
  const uint64_t K1 = LOADBYTES(k + 8, 8);
  const uint64_t N0 = LOADBYTES(npub, 8);
  const uint64_t N1 = LOADBYTES(npub + 8, 8);

  /* initialize */
  state_t s;
  s.x0 = ASCON_80PQ_IV;
  s.x1 = K0;
  s.x2 = K1;
  s.x3 = N0;
  s.x4 = N1;
  P12(&s);
  s.x3 ^= K0;
  s.x4 ^= K1;
  printstate("initialization", &s);

  if (adlen) {
    /* full associated data blocks */
    while (adlen >= ASCON_128_RATE) {
      s.x0 ^= LOADBYTES(ad, 8);
      P6(&s);
      ad += ASCON_128_RATE;
      adlen -= ASCON_128_RATE;
    }
    /* final associated data block */
    s.x0 ^= LOADBYTES(ad, adlen);
    s.x0 ^= PAD(adlen);
    P6(&s);
  }
  /* domain separation */
  s.x4 ^= 1;
  printstate("process associated data", &s);

  /* full ciphertext blocks */
  clen -= CRYPTO_ABYTES;
  while (clen >= ASCON_128_RATE) {
    uint64_t c0 = LOADBYTES(c, 8);
    STOREBYTES(m, s.x0 ^ c0, 8);
    s.x0 = c0;
    P6(&s);
    m += ASCON_128_RATE;
    c += ASCON_128_RATE;
    clen -= ASCON_128_RATE;
  }
  /* final ciphertext block */
  uint64_t c0 = LOADBYTES(c, clen);
  STOREBYTES(m, s.x0 ^ c0, clen);
  s.x0 = CLEARBYTES(s.x0, clen);
  s.x0 |= c0;
  s.x0 ^= PAD(clen);
  c += clen;
  printstate("process ciphertext", &s);

  /* finalize */
  s.x1 ^= K0;
  s.x2 ^= K1;
  P12(&s);
  s.x3 ^= K0;
  s.x4 ^= K1;
  printstate("finalization", &s);

  /* set tag */
  uint8_t t[16];
  STOREBYTES(t, s.x3, 8);
  STOREBYTES(t + 8, s.x4, 8);

  /* verify tag (should be constant time, check compiler output) */
  int result = 0;
  for (int i = 0; i < CRYPTO_ABYTES; ++i) result |= c[i] ^ t[i];
  result = (((result - 1) >> 8) & 1) - 1;

  return result;
}
