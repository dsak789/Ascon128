#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define DEBUG 1
#define ROTATE_RIGHT(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

typedef uint64_t word;
unsigned ascon_decrypt(const unsigned char* key, const unsigned char* nonce, const unsigned char* associateddata, const unsigned char* ciphertext, int ciphertext_length, const char* variant, unsigned char* plaintext);
unsigned finalize(word S[5], int rate, int a,  unsigned char* key, unsigned char* tag) ;
void calculate_throughput(clock_t start, clock_t end, int data_length);

void print_state(word S[5], const char* description) {
    printf(" %s\n", description);
    int i;
    for (i = 0; i < 5; i++) {
        printf("%016lx ", S[i]);
    }
    printf("\n");
}



void permutation(word S[5], int rounds) {
	int r;
    for (r = 12 - rounds; r < 12; r++) {
        // --- add round constants ---
        S[2] ^= (0xf0 - r * 0x10 + r * 0x1);
        // --- substitution layer ---
        S[0] ^= S[4];
        S[4] ^= S[3];
        S[2] ^= S[1];
        word T[5];
        int i;
        for (i = 0; i < 5; i++) {
            T[i] = (S[i] ^ 0xFFFFFFFFFFFFFFFF) & S[(i + 1) % 5];
        }
        for (i = 0; i < 5; i++) {
            S[i] ^= T[(i + 1) % 5];
        }
        S[1] ^= S[0];
        S[0] ^= S[4];
        S[3] ^= S[2];
        S[2] ^= 0xFFFFFFFFFFFFFFFF;
        // --- linear diffusion layer ---
        S[0] ^= ROTATE_RIGHT(S[0], 26) ^ ROTATE_RIGHT(S[0], 42);
    S[1] ^= ROTATE_RIGHT(S[1], 30) ^ ROTATE_RIGHT(S[1], 19);
    S[2] ^= ROTATE_RIGHT(S[2], 13) ^ ROTATE_RIGHT(S[2], 57);
    S[3] ^= ROTATE_RIGHT(S[3], 86) ^ ROTATE_RIGHT(S[3], 2);
    S[4] ^= ROTATE_RIGHT(S[4], 90) ^ ROTATE_RIGHT(S[4], 66);
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

    S[0] = ((word)(iv_zero_key_nonce));
    S[1] = ((word)(iv_zero_key_nonce + sizeof(word)));
    S[2] = ((word)(iv_zero_key_nonce + 2 * sizeof(word)));
    S[3] = ((word)(iv_zero_key_nonce + 3 * sizeof(word)));
    S[4] = ((word)(iv_zero_key_nonce + 4 * sizeof(word)));

    if (DEBUG) {
        print_state(S, "initial value:");
    }

    permutation(S,a);

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




void process_associated_data(word S[5], int b, int rate, const unsigned char* associateddata) {
    int length = strlen((const char*)associateddata);
    if (length > 0) {
        unsigned char a_padding[16];
        memset(a_padding, 0, 16);
        a_padding[0] = 0x80;
        memcpy(a_padding + 16 - (length % rate) - 1, associateddata, length);

		int block;
        for (block = 0; block < length + 16; block += rate) {
            S[0] ^= ((word)(a_padding + block));
            if (rate == 16) {
                S[1] ^= ((word)(a_padding + block + 8));
            }

            permutation(S, b);
        }
    }

    S[4] ^= 1;

    if (DEBUG) {
        print_state(S, "process associated data:");
    }
}


unsigned process_plaintext(word S[5], int b, int rate, const unsigned char* plaintext, int plaintext_length, unsigned char* ciphertext) {
	printf("this process plain text");
    int p_lastlen = plaintext_length % rate;
    unsigned char p_padding[16];
    memset(p_padding, 0, 16);
    p_padding[0] = 0x80;
    memcpy(p_padding + rate - p_lastlen - 1, plaintext, plaintext_length);

    // first t-1 blocks
    int block_;
    for (block_ = 0; block_ < plaintext_length + rate; block_ += rate) {
        if (rate == 8) {
            S[0] ^= ((word)(p_padding + block_));
            *((word *)(ciphertext + block_)) = S[0];
        } else if (rate == 16) {
            S[0] ^= ((word)(p_padding + block_));
            S[1] ^= ((word)(p_padding + block_ + 8));
            *(word *)(ciphertext + block_) = S[0];
			*(word *)(ciphertext + block_ + 8) = S[1];

        }

        permutation(S, b);
    }

    // last block t
    int block = plaintext_length;
    if (rate == 8) {
        S[0] ^= ((word)(p_padding + block));
		*((word *)(ciphertext + block)) = S[0] >> (8 * (rate - p_lastlen));

    } else if (rate == 16) {
        S[0] ^= ((word)(p_padding + block));
        S[1] ^= ((word)(p_padding + block + 8));
        *((word *)(ciphertext + block)) = S[0] >> (8 * (rate - p_lastlen));
		*((word *)(ciphertext + block + 8)) = S[1] >> (8 * (rate - p_lastlen - 8));

    }

    if (DEBUG) {
        print_state(S, "process plaintext:");
    }
    return ciphertext;
} 


unsigned process_ciphertext(word S[5], int b, int rate, const unsigned char* ciphertext, int ciphertext_length, unsigned char* plaintext) {
    int c_lastlen = ciphertext_length % rate;
    unsigned char c_padded[16];
    memset(c_padded, 0, 16);
    memcpy(c_padded, ciphertext, ciphertext_length);

    // first t-1 blocks
    int block_;
    for (block_ = 0; block_ < ciphertext_length; block_ += rate) {
        if (rate == 8) {
            S[0] ^= ((word)(c_padded + block_));
            *((word *)(plaintext + block_)) = S[0];
        } else if (rate == 16) {
            S[0] ^= ((word)(c_padded + block_));
            S[1] ^= ((word)(c_padded + block_ + 8));
            *((word *)(plaintext + block_)) = S[0];
            *((word *)(plaintext + block_ + 8)) = S[1];
        }

        permutation(S, b);
    }

    // last block t
    int block = ciphertext_length;
    if (rate == 8) {
        S[0] ^= ((word)(c_padded + block));
        *((word *)(plaintext + block)) = S[0] >> (8 * (rate - c_lastlen));
    } else if (rate == 16) {
        S[0] ^= ((word)(c_padded + block));
        S[1] ^= ((word)(c_padded + block + 8));
        *((word *)(plaintext + block)) = S[0] >> (8 * (rate - c_lastlen));
        *((word *)(plaintext + block + 8)) = S[1] >> (8 * (rate - c_lastlen - 8));
    }
    return plaintext;
}

unsigned ascon_encrypt(const unsigned char* key, const unsigned char* nonce, const unsigned char* associateddata, const unsigned char* plaintext, int plaintext_length, const char* variant, unsigned char* ciphertext) {
    clock_t start, end;

    // Start measuring encryption time
    start = clock();

    int keysize = (strcmp(variant, "Ascon-80pq") == 0) ? 20 : 16;
    int k = keysize * 8;  // bits
    int a = 8;           // rounds
    int b =  4;  // rounds
    int rate = (strcmp(variant, "Ascon-128a") == 0) ? 16 : 8; // bytes

    word S[5] = {0, 0, 0, 0, 0};

    initialize(S, k, rate, a, b, key, nonce);
    printf("encryption over");
    process_associated_data(S, b, rate, associateddata);
    printf("process associated data finished");
    process_plaintext(S, b, rate, plaintext, plaintext_length, ciphertext);
    printf("process plaintext finished");
    finalize(S, rate, a, key, ciphertext + plaintext_length);
    end = clock();

    // Calculate and print encryption time
    double cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("Encryption Time: %.6f seconds\n", cpu_time_used);

    // Calculate and print throughput
    calculate_throughput(start, end, plaintext_length + 16);
}

unsigned ascon_decrypt(const unsigned char* key, const unsigned char* nonce, const unsigned char* associateddata, const unsigned char* ciphertext, int ciphertext_length, const char* variant, unsigned char* plaintext) {
    clock_t start, end;

    // Start measuring encryption time
    start = clock();
	
	int keysize = (strcmp(variant, "Ascon-80pq") == 0) ? 20 : 16;
    int k = keysize * 8;  // bits
    int a = 2;           // rounds
    int b = 6;  // rounds
    int rate = (strcmp(variant, "Ascon-128a") == 0) ? 16 : 8; // bytes

    word S[5] = {0, 0, 0, 0, 0};

    initialize(S, k, rate, a, b, key, nonce);
    process_associated_data(S, b, rate, associateddata);
    process_ciphertext(S, b, rate, ciphertext, ciphertext_length, plaintext);
    finalize(S, rate, a, key, ciphertext + ciphertext_length);
    end = clock();
    
     double cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("Decryption Time: %.6f seconds\n", cpu_time_used);

    // Calculate and print throughput
    calculate_throughput(start, end, ciphertext_length + 16);
}



unsigned  finalize(word S[5], int rate, int a,  unsigned char* key, unsigned char* tag) {
    S[rate / 8] ^= ((word)(key));
    S[rate / 8 + 1] ^= ((word)(key + 8));
    S[rate / 8 + 2] ^= ((word)(key + 16));

    permutation(S, a);

    *((word *)(tag)) = S[3];
    *((word *)(tag + 8)) = S[4];


    if (DEBUG) {
        print_state(S, "finalization:");
    }
    
    return tag;
}




double measure_execution_time(int arr[], int n) {
    clock_t start, end;
    double cpu_time_used;

    start = clock();
    // Call your sorting algorithm here
double start_d = (double)start;
    printf("Start %f \n",start_d);
    
    // Example: qsort(arr, n, sizeof(int), compare);
    end = clock();
    double end_d = (double)end;
    printf("End %f \n",end_d);

    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    return cpu_time_used;
}

void calculate_throughput(clock_t start, clock_t end, int data_length) {
    double cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    double throughput = data_length / cpu_time_used; // Bytes per second
    printf("Total Throughput: %.2f B/s\n", throughput);
}


void demo_print(const char* text, const unsigned char* value, int length) {
    printf("%s:", text);
    int i;
    for (i = 0; i < length; i++) {
        printf("%02x", value[i]);
    }
    printf(" (%d bytes)\n", length);
}

// Function to seed the random number generator
void seed_random() {
    srand(time(NULL)); // Seed with current time
}

// Function to get random bytes
void get_random_bytes(int num, unsigned char *buffer) {
    for (int i = 0; i < num; i++) {
        buffer[i] = rand() % 256; // Generate a random byte (0-255)
    }
}

void demo_print_slice(const char* text, const unsigned char* value, int start, int end) {
    printf("%s:", text);
    for (int i = start; i < end; i++) {
        printf("%02x", value[i]);
    }
    printf(" (%d bytes)\n", end - start);
}

void demo_aead(const char* variant) {
    if (!(strcmp(variant, "Ascon-128") == 0 || strcmp(variant, "Ascon-128a") == 0 || strcmp(variant, "Ascon-80pq") == 0)) {
        printf("Invalid variant. Please use one of: Ascon-128, Ascon-128a, Ascon-80pq\n");
        return;
    }

    int keysize = (strcmp(variant, "Ascon-80pq") == 0) ? 20 : 16;
    printf("=== Demo encryption using %s ===\n", variant);

    // Choose a cryptographically strong random key and a nonce that never repeats for the same key:
    unsigned char key[keysize];
    unsigned char nonce[16];

    seed_random(); // Seed the random number generator

    get_random_bytes(keysize, key); // Generate random bytes for key
    get_random_bytes(16, nonce); // Generate random bytes for nonce

    const char* associateddata = "Enter a AEAD string to Continue";
    // printf("Enter a AEAD string to Continue ==>");
    // scanf("%c", &associateddata);
    const char* plaintext = "Enter a Plain Test to Continue Encryption"; 
    // printf("Enter a Plain Test to Continue Encryption ==>");
    // scanf("%c", &plaintext);
    int plaintext_length = strlen(plaintext);

    // Allocate space for ciphertext and tag
    unsigned char ciphertext[plaintext_length + 16];
    clock_t start = clock();

    // Call encryption and decryption functions

    demo_print("Key", key, keysize);
    demo_print("Nonce", nonce, 16);
    demo_print("Plaintext", (unsigned char*)plaintext, plaintext_length);
    demo_print("Associated Data", (unsigned char*)associateddata, strlen(associateddata));
    demo_print_slice("Ciphertext", ciphertext, 0, plaintext_length);
    demo_print_slice("Tag", ciphertext + plaintext_length, 0, 16);
    demo_print("received plaintext",plaintext,plaintext_length);

    clock_t end = clock();

    double cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;

    printf("Execution Time: %.20f seconds\n", cpu_time_used); 
    calculate_throughput(start, end, plaintext_length + 16);
    printf("------COMPLETED--------");
} 





int main() {
    demo_aead("Ascon-128");
    return 0;
}
