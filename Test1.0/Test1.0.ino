// Test1.0.ino

#include <Arduino.h>
#include <string.h>

// Include function declarations from encrypt.c
#include "api.h"
#include "ascon.h"
#include "crypto_aead.h"
#include "permutations.h"
#include "printstate.h"
#include "word.h"
#include "encrypt.c"
// #include "decrypt.c"
// Paste the contents of crypto_aead_encrypt and crypto_aead_decrypt functions here

unsigned char m[256]; // Assuming a maximum message length of 256 bytes
unsigned long long mlen;
unsigned char ad[256]; // Assuming a maximum associated data length of 256 bytes
unsigned long long adlen;
unsigned char c[512]; // Assuming a maximum ciphertext length of 512 bytes
unsigned long long clen;
const unsigned char nsec[16]; // Nonce security, assuming 16 bytes (all zeros)
const unsigned char npub[16] = {0}; // Nonce, assuming 16 bytes (all zeros)
const unsigned char k[32] = {0}; // Key, assuming 32 bytes (all zeros)

void setup() {
    Serial.begin(9600);

    // Example plaintext
    const char* plaintext = "Hello Ascon Coders";
    mlen = strlen(plaintext);
    memcpy(m, plaintext, mlen);

    // Example associated data
    const char* associated_data = "Some additional data";
    adlen = strlen(associated_data);
    memcpy(ad, associated_data, adlen);

    // Perform encryption
    int encrypt_result = crypto_aead_encrypt(c, &clen, m, mlen, ad, adlen, nsec, npub, k);
    // Check if encryption was successful
    if (encrypt_result == 0) {
        // Encryption successful, print the ciphertext
        Serial.println("\nEncryption successful. \nCiphertext: ");
        for (unsigned long long i = 0; i < clen; ++i) {
            Serial.print(c[i], HEX);
            Serial.print(" ");
        }
        
        Serial.println("\n------Encryption End------");
        Serial.println();

        // Perform decryption
        int decrypt_result = crypto_aead_decrypt(m, &mlen, nsec, c, clen, ad, adlen, npub, k);

        // Check if decryption was successful
        if (decrypt_result == 0) {
            // Decryption successful, print the plaintext
            Serial.print("Decryption successful. \nPlaintext: ");
            for (unsigned long long i = 0; i < mlen; ++i) {
                Serial.print((char)m[i]);
            }
            
          Serial.println("\n------Decryption End------");
            Serial.println();
        } else {
            // Decryption failed
            Serial.println("Decryption failed.");
        }
    } else {
        // Encryption failed
        Serial.println("Encryption failed.");
    }
}

void loop() {
    // Nothing to do in the loop
}
