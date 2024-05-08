#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define WORD uint64_t
#define ROTR(x, r) ((x >> r) | (x << (64 - r)))

#define MAX(x, y) (((x) > (y)) ? (x) : (y))

#define RATE_128 8
#define RATE_128A 16
#define RATE_80PQ 8

#define DEBUG 0
#define DEBUG_PERMUTATION 0

typedef struct {
    WORD S[5];
} AsconState;

void ascon_permutation(AsconState *S, int rounds);
void ascon_initialize(AsconState *S, int k, int rate, int a, int b, uint8_t *key, uint8_t *nonce);
void ascon_process_associated_data(AsconState *S, int b, int rate, uint8_t *associateddata);
void ascon_process_plaintext(AsconState *S, int b, int rate, uint8_t *plaintext, uint8_t *ciphertext);
void ascon_process_ciphertext(AsconState *S, int b, int rate, uint8_t *ciphertext, int clen, uint8_t *plaintext);
void ascon_finalize(AsconState *S, int rate, int a, uint8_t *key);
void printstate(AsconState *S, char *description);  
void printwords(AsconState *S, char *description);

WORD to_uint64(uint8_t *bytes);
void to_bytes(WORD val, uint8_t *bytes);
WORD bytes_to_state(uint8_t *bytes);
void int_to_bytes(WORD integer, uint8_t *bytes, int nbytes);

void demo_aead(char *variant);

int main() {
    demo_aead("Ascon-128");
    return 0;
}

void ascon_permutation(AsconState *S, int rounds) {
    int r;
    if (DEBUG_PERMUTATION) printwords(S, "permutation input:");
    for (r = 12 - rounds; r < 12; ++r) {
        S->S[2] ^= (WORD)(0xf0 - r * 0x10 + r * 0x1);
        if (DEBUG_PERMUTATION) printwords(S, "round constant addition:");

        // --- substitution layer ---
        S->S[0] ^= S->S[4];
        S->S[4] ^= S->S[3];
        S->S[2] ^= S->S[1];

        WORD T[5];
        int i;
        for (i = 0; i < 5; ++i) {
            T[i] = (S->S[i] ^ 0xFFFFFFFFFFFFFFFF) & S->S[(i + 1) % 5];
        }
        for (i = 0; i < 5; ++i) {
            S->S[i] ^= T[(i + 1) % 5];
        }
        S->S[1] ^= S->S[0];
        S->S[0] ^= S->S[4];
        S->S[3] ^= S->S[2];
        S->S[2] ^= 0xFFFFFFFFFFFFFFFFULL;
        if (DEBUG_PERMUTATION) printwords(S, "substitution layer:");

        // --- linear diffusion layer ---
        S->S[0] ^= ROTR(S->S[0], 19) ^ ROTR(S->S[0], 28);
        S->S[1] ^= ROTR(S->S[1], 61) ^ ROTR(S->S[1], 39);
        S->S[2] ^= ROTR(S->S[2], 1) ^ ROTR(S->S[2], 6);
        S->S[3] ^= ROTR(S->S[3], 10) ^ ROTR(S->S[3], 17);
        S->S[4] ^= ROTR(S->S[4], 7) ^ ROTR(S->S[4], 41);
        if (DEBUG_PERMUTATION) printwords(S, "linear diffusion layer:");
    }
}

void ascon_initialize(AsconState *S, int k, int rate, int a, int b, uint8_t *key, uint8_t *nonce) {
	printf("\ninitialise");
    uint8_t iv_zero_key_nonce[40];
    int i;
    for (i = 0; i < 40; ++i) {
        iv_zero_key_nonce[i] = 0;
    }
    iv_zero_key_nonce[0] = k;
    iv_zero_key_nonce[1] = rate * 8;
    iv_zero_key_nonce[2] = a;
    iv_zero_key_nonce[3] = b;
    memcpy(&iv_zero_key_nonce[20 - k], key, k);
    memcpy(&iv_zero_key_nonce[36], nonce, 16);

    S->S[0] = bytes_to_state(iv_zero_key_nonce);
    if (DEBUG) printstate(S, "initial value:");

    ascon_permutation(S, a);

    uint8_t zero_key[40];
    memset(zero_key, 0, 40 - k);
    memcpy(&zero_key[40 - k], key, k);

    AsconState zero_key_state;
    zero_key_state.S[0] = bytes_to_state(zero_key);

    S->S[0] ^= zero_key_state.S[0];
    S->S[1] ^= zero_key_state.S[1];
    S->S[2] ^= zero_key_state.S[2];
    S->S[3] ^= zero_key_state.S[3];
    S->S[4] ^= zero_key_state.S[4];
    if (DEBUG) printstate(S, "initialization:");
    printf("\n initialise is over");
}

void ascon_process_associated_data(AsconState *S, int b, int rate, uint8_t *associateddata) {
	printf(" \nprocess associated data");
	printf(" \nprocess associated data is middle");
	printf("\n associateddata is ");
   size_t ad_block_size = 10 + (rate - (10 % rate)) % rate;
    uint8_t *a_padded = (uint8_t *)malloc(ad_block_size);
    printf("\n associateddata is 2");
    if (!a_padded) {
    	printf("\n associateddata is 3 ");
        fprintf(stderr, "Failed to allocate memory for associated data processing.\n");
        return;
    }
    printf("\n associateddata is 4 ");
    memcpy(a_padded, associateddata, 10);
    a_padded[10] = 0x80; // Padding
    memset(a_padded + 10 + 1, 0, ad_block_size - 10 - 1);
    
    size_t i;

    for (i = 0; i < ad_block_size; i += rate) {
        S->S[0] ^= bytes_to_state(&a_padded[i]);
        if (rate == 16) {
            S->S[1] ^= bytes_to_state(&a_padded[i + 8]);
        }
        ascon_permutation(S, b);
    }
    S->S[4] ^= 1;
    free(a_padded);
   
    if (DEBUG) printstate(S, "process associated data:");
    printf(" \nprocess associated data completed ");
}

void ascon_process_plaintext(AsconState *S, int b, int rate, uint8_t *plaintext, uint8_t *ciphertext) {
    int p_lastlen = strlen((char *)plaintext) % rate;
    uint8_t p_padding[16];
    p_padding[0] = 0x80;
    memset(&p_padding[1], 0, rate - p_lastlen - 1);
    uint8_t *p_padded = (uint8_t *)malloc(strlen((char *)plaintext) + rate - p_lastlen - 1);
    memcpy(p_padded, plaintext, strlen((char *)plaintext));
    memcpy(&p_padded[strlen((char *)plaintext)], p_padding, rate - p_lastlen - 1);

    // first t-1 blocks
    int block;
    for (block = 0; block < strlen((char *)p_padded) - rate; block += rate) {
        if (rate == 8) {
            S->S[0] ^= to_uint64(&p_padded[block]);
            to_bytes(S->S[0], &ciphertext[block]);
        } else if (rate == 16) {
            S->S[0] ^= to_uint64(&p_padded[block]);
            S->S[1] ^= to_uint64(&p_padded[block + 8]);
            to_bytes(S->S[0], &ciphertext[block]);
            to_bytes(S->S[1], &ciphertext[block + 8]);
        }
        ascon_permutation(S, b);
    }

    // last block t
    block = strlen((char *)p_padded) - rate;
    if (rate == 8) {
        S->S[0] ^= to_uint64(&p_padded[block]);
        to_bytes(S->S[0], &ciphertext[block]);
    } else if (rate == 16) {
        S->S[0] ^= to_uint64(&p_padded[block]);
        S->S[1] ^= to_uint64(&p_padded[block + 8]);
        to_bytes(S->S[0], &ciphertext[block]);
        to_bytes(S->S[1], &ciphertext[block + 8]);
    }
    if (DEBUG) printstate(S, "process plaintext:");
    free(p_padded);
}

void ascon_process_ciphertext(AsconState *S, int b, int rate, uint8_t *ciphertext, int clen, uint8_t *plaintext) {
    int c_lastlen = clen % rate;
    uint8_t *c_padded = (uint8_t *)malloc(clen + rate - c_lastlen);
    memcpy(c_padded, ciphertext, clen + rate - c_lastlen);

    // first t-1 blocks
    int block;
    for (block = 0; block < clen - rate; block += rate) {
        if (rate == 8) {
            WORD Ci = to_uint64(&c_padded[block]);
            int_to_bytes(S->S[0] ^ Ci, &plaintext[block], 8);
            S->S[0] = Ci;
        } else if (rate == 16) {
            WORD Ci[2];
            Ci[0] = to_uint64(&c_padded[block]);
            Ci[1] = to_uint64(&c_padded[block + 8]);
            int_to_bytes(S->S[0] ^ Ci[0], &plaintext[block], 8);
            int_to_bytes(S->S[1] ^ Ci[1], &plaintext[block + 8], 8);
            S->S[0] = Ci[0];
            S->S[1] = Ci[1];
        }
        ascon_permutation(S, b);
    }

    // last block t
    block = clen - rate;
    if (rate == 8) {
        WORD c_padding1 = (WORD)(0x80 << (rate - c_lastlen - 1) * 8);
        WORD c_mask = (WORD)(0xFFFFFFFFFFFFFFFF >> (c_lastlen * 8));
        WORD Ci = to_uint64(&c_padded[block]);
        int_to_bytes(Ci ^ S->S[0], &plaintext[block], MAX(8, c_lastlen));
        S->S[0] = Ci ^ (S->S[0] & c_mask) ^ c_padding1;
    } else if (rate == 16) {
        int c_lastlen_word = c_lastlen % 8;
        WORD c_padding1 = (WORD)(0x80 << (8 - c_lastlen_word - 1) * 8);
        WORD c_mask = (WORD)(0xFFFFFFFFFFFFFFFF >> (c_lastlen_word * 8));
        WORD Ci[2];
        Ci[0] = to_uint64(&c_padded[block]);
        Ci[1] = to_uint64(&c_padded[block + 8]);
        int_to_bytes(S->S[0] ^ Ci[0], &plaintext[block], MAX(8, c_lastlen));
        if (c_lastlen < 8) {
            S->S[0] = Ci[0] ^ (S->S[0] & c_mask) ^ c_padding1;
        } else {
            S->S[0] = Ci[0];
            S->S[1] = Ci[1] ^ (S->S[1] & c_mask) ^ c_padding1;
        }
    }
    if (DEBUG) printstate(S, "process ciphertext:");
    free(c_padded);
}

void ascon_finalize(AsconState *S, int rate, int a, uint8_t *key) {
    S->S[rate / 8 + 0] ^= to_uint64(&key[0]);
    S->S[rate / 8 + 1] ^= to_uint64(&key[8]);
    S->S[rate / 8 + 2] ^= to_uint64(&key[16]) + 0xFFFFFFFFFFFFFFFF;

    ascon_permutation(S, a);

    S->S[3] ^= to_uint64(&key[16]);
    S->S[4] ^= to_uint64(&key[24]);
    if (DEBUG) printstate(S, "finalization:");
}

void printstate(AsconState *S, char *description) {
    printf(" %s\n", description);
    printf(" ");
    int i;
    for (i = 0; i < 5; ++i) {
        printf("%016llx ", S->S[i]);
    }
    printf("\n");
}

void printwords(AsconState *S, char *description) {
    printf(" %s\n", description);
    printf(" ");
    int i;
    for (i = 0; i < 5; ++i) {
        printf("x%d=%016llx ", i, S->S[i]);
    }
    printf("\n");
}

WORD to_uint64(uint8_t *bytes) {
    WORD val = 0;
    int i;
    for (i = 0; i < 8; ++i) {
        val |= ((WORD)bytes[i]) << ((7 - i) * 8);
    }
    return val;
}

void to_bytes(WORD val, uint8_t *bytes) {
    int i;
    for (i = 0; i < 8; ++i) {
        bytes[i] = (uint8_t)(val >> ((7 - i) * 8));
    }
}

WORD bytes_to_state(uint8_t *bytes) {
    WORD val = 0;
    int i;
    for (i = 0; i < 5; ++i) {
        val |= to_uint64(&bytes[8 * i]) << (64 * i);
    }
    return val;
}

void int_to_bytes(WORD integer, uint8_t *bytes, int nbytes) {
    int i;
    for (i = 0; i < nbytes; ++i) {
        bytes[i] = (uint8_t)((integer >> ((nbytes - 1 - i) * 8)) % 256);
    }
}

void demo_aead(char *variant) {
    printf("=== demo encryption using %s ===\n", variant);

    int keysize = strcmp(variant, "Ascon-80pq") == 0 ? 20 : 16;
    uint8_t *key = (uint8_t *)malloc(keysize);
    uint8_t *nonce = (uint8_t *)malloc(16);

    // choose a cryptographically strong random key and a nonce that never repeats for the same key:
    int i;
    for (i = 0; i < keysize; ++i) {
        key[i] = (uint8_t)rand(); // Replace rand() with a secure random number generator
    }
    for (i = 0; i < 16; ++i) {
        nonce[i] = (uint8_t)rand(); // Replace rand() with a secure random number generator
    }

    uint8_t associateddata[] = "ASCON";
    uint8_t plaintext[] = "ascon";
    int plaintext_length = strlen((char *)plaintext);

    uint8_t *ciphertext = (uint8_t *)malloc(plaintext_length + 16);
    uint8_t *receivedplaintext = (uint8_t *)malloc(plaintext_length);
    size_t adlen = sizeof(associateddata);

    AsconState S;
    printf("..");
    ascon_initialize(&S, keysize, RATE_128A, 12, 8, key, nonce);
    printf("\ninitialise call next method");
	ascon_process_associated_data(&S, 8, RATE_128A, associateddata);
    ascon_process_plaintext(&S, 8, RATE_128A, plaintext, ciphertext);

    printf("ciphertext: ");
    for (i = 0; i < plaintext_length; ++i) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    ascon_finalize(&S, RATE_128A, 12, key);

    ascon_initialize(&S, keysize, RATE_128A, 12, 8, key, nonce);
    ascon_process_associated_data(&S, 8, RATE_128A, associateddata);
    ascon_process_ciphertext(&S, 8, RATE_128A, ciphertext, plaintext_length, receivedplaintext);

    printf("received plaintext: %s\n", receivedplaintext);

    free(key);
    free(nonce);
    free(ciphertext);
    free(receivedplaintext);
}
