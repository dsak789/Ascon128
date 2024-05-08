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

unsigned char m[256]; // Assuming a maximum message length of 256 bytes
unsigned long long mlen;
unsigned char ad[256]; // Assuming a maximum associated data length of 256 bytes
unsigned long long adlen;
unsigned char c[512]; // Assuming a maximum ciphertext length of 512 bytes
unsigned long long clen;
const unsigned char nsec[16] = {0}; // Nonce security, assuming 16 bytes (all zeros)
unsigned char npub[16]; // Nonce, to be generated randomly
unsigned char k[16]; // Key, to be generated randomly

void setup() {
    Serial.begin(9600);

    // Generate random key (32 bytes)
    randomSeed(analogRead(0)); // Seed for random number generation
    for (int i = 0; i < 16; ++i) {
        k[i] = random(256); // Random byte between 0 and 255
    }

    // Example plaintext
    const char* plaintext = "ASCON128";
    mlen = strlen(plaintext);
    memcpy(m, plaintext, mlen);

    // Example associated data
    const char* associated_data = "Something";
    adlen = strlen(associated_data);
    memcpy(ad, associated_data, adlen);

    // Perform encryption
    unsigned long start_encrypt = micros();
    int encrypt_result = crypto_aead_encrypt(c, &clen, m, mlen, ad, adlen, nsec, npub, k);
    unsigned long end_encrypt = micros();
    double encrypt_time = (end_encrypt - start_encrypt) / 1000.0;
    // Check if encryption was successful
    if (encrypt_result == 0) {
        // Encryption successful, print the ciphertext
        Serial.println("\nEncryption Start------->");
        Serial.print("\nEncryption successful. \nCiphertext: ");
        for (unsigned long long i = 0; i < clen; ++i) {
            Serial.print(c[i], HEX);
            Serial.print(" ");
        }
        Serial.print("\nEncryption Time ------> ");
        Serial.print(encrypt_time, 7);
        Serial.println(" nano secs\n------Encryption End------");
        Serial.print("\nCalculated Aavalanche Result---> ");
        Serial.print(calculate_avalanche_effect(m, mlen, ad, adlen, npub, k));
        Serial.println("%\n------avalanche End------");
        // Perform decryption
        unsigned long start_decrypt = micros();
        int decrypt_result = crypto_aead_decrypt(m, &mlen, nsec, c, clen, ad, adlen, npub, k);
        unsigned long end_decrypt = micros();
        double decrypt_time = (end_decrypt - start_decrypt) / 1000.0;
        // Check if decryption was successful
        if (decrypt_result == 0) {
            // Decryption successful, print the plaintext
            Serial.print("\nDecryption Start-------->");
            Serial.print("\nDecryption successful. \nPlaintext: ");
            for (unsigned long long i = 0; i < mlen; ++i) {
                Serial.print((char)m[i]);
            }
            Serial.print("\nDecryption Time ------> ");
            Serial.print(decrypt_time, 7);
            Serial.println(" nano secs\n---Decryption End----");

            // Print throughput
            double throughput_encrypt = mlen / encrypt_time;
            double throughput_decrypt = mlen / decrypt_time;
            Serial.print("\nThroughputs---------> ");
            Serial.print("\nEncryption Throughput----> ");
            Serial.print(throughput_encrypt, 5);
            Serial.println(" bytes/second");
            Serial.print("Decryption Throughput----> ");
            Serial.print(throughput_decrypt, 5);
            Serial.print(" bytes/second");
            Serial.print("\n<--------Throughputs Calculations End-------> ");
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
