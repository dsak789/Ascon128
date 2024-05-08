#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define DEBUG 1

typedef uint64_t word;

void print_state(word S[5], const char* description) {
    printf(" %s\n", description);
    for (int i = 0; i < 5; i++) {
        printf("%016lx ", S[i]);
    }
    printf("\n");
}

void permutation(word S[5], int rounds) {
    for (int r = 12 - rounds; r < 12; r++) {
        // --- add round constants ---
        S[2] ^= (0xf0 - r * 0x10 + r * 0x1);
        // --- substitution layer ---
        S[0] ^= S[4];
        S[4] ^= S[3];
        S[2] ^= S[1];
        word T[5];
        for (int i = 0; i < 5; i++) {
            T[i] = (S[i] ^ 0xFFFFFFFFFFFFFFFF) & S[(i + 1) % 5];
        }
        for (int i = 0; i < 5; i++) {
            S[i] ^= T[(i + 1) % 5];
        }
        S[1] ^= S[0];
        S[0] ^= S[4];
        S[3] ^= S[2];
        S[2] ^= 0xFFFFFFFFFFFFFFFF;
        // --- linear diffusion layer ---
        S[0] ^= ((S[0] >> 19) | ((S[0] & ((1ULL << 19) - 1)) << (64 - 19))) ^ ((S[0] >> 28) | ((S[0] & ((1ULL << 28) - 1)) << (64 - 28)));
        S[1] ^= ((S[1] >> 61) | ((S[1] & ((1ULL << 61) - 1)) << (64 - 61))) ^ ((S[1] >> 39) | ((S[1] & ((1ULL << 39) - 1)) << (64 - 39)));
        S[2] ^= ((S[2] >> 1) | ((S[2] & ((1ULL << 1) - 1)) << (64 - 1))) ^ ((S[2] >> 6) | ((S[2] & ((1ULL << 6) - 1)) << (64 - 6)));
        S[3] ^= ((S[3] >> 10) | ((S[3] & ((1ULL << 10) - 1)) << (64 - 10))) ^ ((S[3] >> 17) | ((S[3] & ((1ULL << 17) - 1)) << (64 - 17)));
        S[4] ^= ((S[4] >> 7) | ((S[4] & ((1ULL << 7) - 1)) << (64 - 7))) ^ ((S[4] >> 41) | ((S[4] & ((1ULL << 41) - 1)) << (64 - 41)));
    }
}

void initialize(word S[5], int k, int rate, int a, int b, const unsigned char* key, const unsigned char* nonce) {
    unsigned char iv_zero_key_nonce[40];
    memcpy(iv_zero_key_nonce, &k, sizeof(int));
    memcpy(iv_zero_key_nonce + sizeof(int), &rate, sizeof(int));
    memcpy(iv_zero_key_nonce + 2 * sizeof(int), &a, sizeof(int));
    memcpy(iv_zero_key_nonce + 3 * sizeof(int), &b, sizeof(int));
    memcpy(iv_zero_key_nonce + 4 * sizeof(int), key, 20);
    memcpy(iv_zero_key_nonce + 4 * sizeof(int) + 20, nonce, 16);

    S[0] = *((word*)(iv_zero_key_nonce));
    S[1] = *((word*)(iv_zero_key_nonce + sizeof(word)));
    S[2] = *((word*)(iv_zero_key_nonce + 2 * sizeof(word)));
    S[3] = *((word*)(iv_zero_key_nonce + 3 * sizeof(word)));
    S[4] = *((word*)(iv_zero_key_nonce + 4 * sizeof(word)));

    if (DEBUG) {
        print_state(S, "initial value:");
    }

    permutation(S, a);

    word zero_key[5];
    memcpy(zero_key, key, 16);
    memset(zero_key + 4, 0, sizeof(word));
    S[0] ^= zero_key[0];
    S[1] ^= zero_key[1];
    S[2] ^= zero_key[2];
    S[3] ^= zero_key[3];
    S[4] ^= zero_key[4];

    if (DEBUG) {
        print_state(S, "initialization:");
    }
}

void finalize(word S[5], int rate, int a, const unsigned char* key, unsigned char* tag) {
    S[rate / 8] ^= *((word*)(key));
    S[rate / 8 + 1] ^= *((word*)(key + 8));
    S[rate / 8 + 2] ^= *((word*)(key + 16));

    permutation(S, a);

    *((word*)(tag)) = S[3];
    *((word*)(tag + 8)) = S[4];

    if (DEBUG) {
        print_state(S, "finalization:");
    }
}

void process_associated_data(word S[5], int b, int rate, const unsigned char* associateddata) {
    int length = strlen((const char*)associateddata);
    if (length > 0) {
        unsigned char a_padding[16];
        memset(a_padding, 0, 16);
        a_padding[0] = 0x80;
        memcpy(a_padding + 16 - (length % rate) - 1, associateddata, length);

        for (int block = 0; block < length + 16; block += rate) {
            S[0] ^= *((word*)(a_padding + block));
            if (rate == 16) {
                S[1] ^= *((word*)(a_padding + block + 8));
            }

            permutation(S, b);
        }
    }

    S[4] ^= 1;

    if (DEBUG) {
        print_state(S, "process associated data:");
    }
}

void process_plaintext(word S[5], int b, int rate, const unsigned char* plaintext, int plaintext_length, unsigned char* ciphertext) {
    int p_lastlen = plaintext_length % rate;
    unsigned char p_padding[16];
    memset(p_padding, 0, 16);
    p_padding[0] = 0x80;
    memcpy(p_padding + rate - p_lastlen - 1, plaintext, plaintext_length);

    // first t-1 blocks
    for (int block = 0; block < plaintext_length + rate; block += rate) {
        if (rate == 8) {
            S[0] ^= *((word*)(p_padding + block));
            *((word*)(ciphertext + block)) = S[0];
        } else if (rate == 16) {
            S[0] ^= *((word*)(p_padding + block));
            S[1] ^= *((word*)(p_padding + block + 8));
            *((word*)(ciphertext + block)) = S[0];
            *((word*)(ciphertext + block + 8)) = S[1];
        }

        permutation(S, b);
    }

    // last block t
    int block = plaintext_length;
    if (rate == 8) {
        S[0] ^= *((word*)(p_padding + block));
        *((word*)(ciphertext + block)) = S[0] >> (8 * (rate - p_lastlen));
    } else if (rate == 16) {
        S[0] ^= *((word*)(p_padding + block));
        S[1] ^= *((word*)(p_padding + block + 8));
        *((word*)(ciphertext + block)) = S[0] >> (8 * (rate - p_lastlen));
        *((word*)(ciphertext + block + 8)) = S[1] >> (8 * (rate - p_lastlen - 8));
    }

    if (DEBUG) {
        print_state(S, "process plaintext:");
    }
}

void ascon_encrypt(const unsigned char* key, const unsigned char* nonce, const unsigned char* associateddata, const unsigned char* plaintext, int plaintext_length, const char* variant, unsigned char* ciphertext) {
    int keysize = (strcmp(variant, "Ascon-80pq") == 0) ? 20 : 16;
    int k = keysize * 8;  // bits
    int a = 12;           // rounds
    int b = (strcmp(variant, "Ascon-128a") == 0) ? 8 : 6;  // rounds
    int rate = (strcmp(variant, "Ascon-128a") == 0) ? 16 : 8; // bytes

    word S[5] = {0, 0, 0, 0, 0};

    initialize(S, k, rate, a, b, key, nonce);
    process_associated_data(S, b, rate, associateddata);
    process_plaintext(S, b, rate, plaintext, plaintext_length, ciphertext);
    finalize(S, rate, a, key, ciphertext + plaintext_length);

    // Print the result if DEBUG is enabled
    if (DEBUG) {
        printf("=== Result ===\n");
        printf("Ciphertext and Tag: ");
        for (int i = 0; i < plaintext_length + 16; i++) {
            printf("%02x", ciphertext[i]);
        }
        printf("\n");
    }
}

void demo_print(const char* text, const unsigned char* value, int length) {
    printf("%s:", text);
    for (int i = 0; i < length; i++) {
        printf("%02x", value[i]);
    }
    printf(" (%d bytes)\n", length);
}

void demo_aead(const char* variant) {
    if (!(strcmp(variant, "Ascon-128") == 0 || strcmp(variant, "Ascon-128a") == 0 || strcmp(variant, "Ascon-80pq") == 0)) {
        printf("Invalid variant. Please use one of: Ascon-128, Ascon-128a, Ascon-80pq\n");
        return;
    }

    int keysize = (strcmp(variant, "Ascon-80pq") == 0) ? 20 : 16;
    printf("=== Demo encryption using %s ===\n", variant);

    // Choose a cryptographically strong random key and a nonce that never repeats for the same key:
    unsigned char key[20] = {0}; // Replace this with actual key generation
    unsigned char nonce[16] = {0}; // Replace this with actual nonce generation

    const char* associateddata = "ASCON";
    const char* plaintext = "ascon";
    int plaintext_length = strlen(plaintext);

    // Allocate space for ciphertext and tag
    unsigned char ciphertext[plaintext_length + 16];

    void ascon_encrypt(const unsigned char* key, const unsigned char* nonce, const unsigned char* associateddata, const unsigned char* plaintext, int plaintext_length, const char* variant, unsigned char* ciphertext);


    demo_print("Key", key, keysize);
    demo_print("Nonce", nonce, 16);
    demo_print("Plaintext", (unsigned char*)plaintext, plaintext_length);
    demo_print("Associated Data", (unsigned char*)associateddata, strlen(associateddata));
    demo_print("Ciphertext", ciphertext, plaintext_length);
    demo_print("Tag", ciphertext + plaintext_length, 16);
}

int main() {
    demo_aead("Ascon-128");
    return 0;
}

