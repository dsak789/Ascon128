
#include <Arduino.h>
#include <string.h>
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

  // Generate random key (16 bytes)
  randomSeed(analogRead(A0)); // Seed for random number generation
  for (int i = 0; i < 16; ++i) {
    k[i] = random(256); // Random byte between 0 and 255
  }

  // Input the plaintext
  Serial.println("\nEnter the plaintext:");
  while (Serial.available() == 0);
  String plaintext = Serial.readStringUntil('\n');
  plaintext.toCharArray((char*)m, sizeof(m));
  mlen = plaintext.length();

  // Input the associated data
  Serial.println("Enter the associated data:");
  while (Serial.available() == 0);
  String associated_data = Serial.readStringUntil('\n');
  associated_data.toCharArray((char*)ad, sizeof(ad));
  adlen = associated_data.length();

  // Perform encryption
  unsigned long start_encrypt = millis();
  int encrypt_result = crypto_aead_encrypt(c, &clen, m, mlen, ad, adlen, nsec, npub, k);
  unsigned long end_encrypt = millis();

  // Check if encryption was successful
  if (encrypt_result == 0) {
    // Encryption successful, print the tag and ciphertext
    Serial.println("Encryption successful.\nTag:");
    print_hex(c + clen - CRYPTO_ABYTES, CRYPTO_ABYTES);
    Serial.println("\nCiphertext:");
    for (unsigned long long i = 0; i < clen; ++i) {
            Serial.print(c[i], HEX);
            Serial.print(" ");
        }

    // Perform decryption
    unsigned long start_decrypt = millis();
    int decrypt_result = crypto_aead_decrypt(m, &mlen, nsec, c, clen, ad, adlen, npub, k);
    unsigned long end_decrypt = millis();

    // Check if decryption was successful
    if (decrypt_result == 0) {
      // Decryption successful, print the plaintext
      Serial.print("Decryption successful. Plaintext: ");
       for (unsigned long long i = 0; i < mlen; ++i) {
                Serial.print((char)m[i]);
            }
      // Calculate and print throughput
      double encrypt_time = (end_encrypt - start_encrypt) / 1000.0; // in seconds
      double decrypt_time = (end_decrypt - start_decrypt) / 1000.0; // in seconds
      double throughput_encrypt = mlen / encrypt_time;
      double throughput_decrypt = mlen / decrypt_time;
      Serial.print("Encryption Time: ");
      Serial.print(encrypt_time, 9);
      Serial.println(" seconds");
      Serial.print("Decryption Time: ");
      Serial.print(decrypt_time, 9);
      Serial.println(" seconds");
      Serial.print("Encryption Throughput: ");
      Serial.print(throughput_encrypt);
      Serial.println(" bytes/second");
      Serial.print("Decryption Throughput: ");
      Serial.print(throughput_decrypt);
      Serial.println(" bytes/second");
    } else {
      // Decryption failed
      Serial.println("Decryption failed.");
    }
  } else {
    // Encryption failed
    Serial.println("Encryption failed.");
  }

  // Calculate and print the avalanche effect
  calculate_avalanche_effect(m, mlen, ad, adlen, npub, k);
}

void loop() {
  // Empty loop, as the code is designed to run once in the setup function
}
