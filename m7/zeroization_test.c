/* M7 controlled test: checks designated key buffer only, not all secret copies. */
#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#define KEY_SIZE 32

static void print_hex(const char *label, const unsigned char *data, size_t n) {
    printf("%s", label);
    for (size_t i = 0; i < n; ++i) printf("%02x", data[i]);
    putchar('\n');
}
int main(void) {
    unsigned char key[KEY_SIZE];
    if (RAND_bytes(key, sizeof key) != 1) {
        fprintf(stderr, "[M7] RAND_bytes failed\n");
        return 1;
    }
    print_hex("[M7] Before zeroization: ", key, sizeof key);
    OPENSSL_cleanse(key, sizeof key);
    print_hex("[M7] After zeroization:  ", key, sizeof key);
    unsigned char zeros[KEY_SIZE] = {0};
    int pass = memcmp(key, zeros, sizeof key) == 0;
    printf("[M7] Zeroization verification: %s\n", pass ? "PASS" : "FAIL");
    OPENSSL_cleanse(key, sizeof key);
    return pass ? 0 : 1;
}
