#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#define KEY_SIZE    32
#define IV_SIZE     12
#define TAG_SIZE    16
#define BUFFER_SIZE 64


/*
 * Print bytes in hexadecimal format.
 */
void print_hex(const char *label,
               const unsigned char *data,
               int len)
{
    int i;

    printf("%s", label);

    for (i = 0; i < len; i++)
    {
        printf("%02x", data[i]);
    }

    printf("\n");
}


/*
 * AES-256-GCM encryption.
 */
int encrypt_gcm(const unsigned char *plaintext,
                int plaintext_len,
                const unsigned char *key,
                const unsigned char *iv,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL)
    {
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx,
                           EVP_aes_256_gcm(),
                           NULL,
                           NULL,
                           NULL) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx,
                           NULL,
                           NULL,
                           key,
                           iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptUpdate(ctx,
                          ciphertext,
                          &len,
                          plaintext,
                          plaintext_len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx,
                            ciphertext + len,
                            &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx,
                            EVP_CTRL_GCM_GET_TAG,
                            TAG_SIZE,
                            tag) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


/*
 * AES-256-GCM decryption.
 */
int decrypt_gcm(const unsigned char *ciphertext,
                int ciphertext_len,
                const unsigned char *tag,
                const unsigned char *key,
                const unsigned char *iv,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL)
    {
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx,
                           EVP_aes_256_gcm(),
                           NULL,
                           NULL,
                           NULL) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx,
                           NULL,
                           NULL,
                           key,
                           iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptUpdate(ctx,
                          plaintext,
                          &len,
                          ciphertext,
                          ciphertext_len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx,
                            EVP_CTRL_GCM_SET_TAG,
                            TAG_SIZE,
                            (void *)tag) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    ret = EVP_DecryptFinal_ex(ctx,
                              plaintext + len,
                              &len);

    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0)
    {
        plaintext_len += len;
        return plaintext_len;
    }

    return -1;
}


/*
 * M3 vulnerable frame.
 *
 * The intended memory layout is:
 *
 *     +---------------------------+
 *     | input[64]                 |
 *     +---------------------------+
 *     | exposed_key[32]           |
 *     +---------------------------+
 *
 * The program later reads 96 bytes starting from input,
 * even though input contains only 64 bytes.
 *
 * This demonstrates an information-disclosure vulnerability.
 */
struct vulnerable_frame
{
    char input[BUFFER_SIZE];
    unsigned char exposed_key[KEY_SIZE];
};


int main(void)
{
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    unsigned char tag[TAG_SIZE];

    unsigned char ciphertext[BUFFER_SIZE];
    unsigned char decrypted[BUFFER_SIZE];

    const unsigned char plaintext[] =
        "Confidential KeyLeak message";

    int plaintext_len;
    int ciphertext_len;
    int decrypted_len;

    /*
     * M3 vulnerable frame.
     */
    struct vulnerable_frame frame;

    printf("========================================\n");
    printf("       KeyLeak - M1/M2/M3 App\n");
    printf("========================================\n\n");


    /*
     * ========================================
     * M1: AES-256-GCM setup
     * ========================================
     */

    /*
     * Generate AES-256 key.
     */
    if (RAND_bytes(key, KEY_SIZE) != 1)
    {
        fprintf(stderr, "Error: RAND_bytes() failed\n");
        return EXIT_FAILURE;
    }


    /*
     * Generate GCM IV.
     */
    if (RAND_bytes(iv, IV_SIZE) != 1)
    {
        fprintf(stderr, "Error: RAND_bytes() failed for IV\n");
        return EXIT_FAILURE;
    }


    plaintext_len = strlen((const char *)plaintext);


    printf("[M1] AES-256-GCM key generated successfully.\n");
    printf("[M1] Key size: %d bytes (%d bits)\n",
           KEY_SIZE,
           KEY_SIZE * 8);


    /*
     * Print the original key for lab verification.
     *
     * In the final demonstration this can be removed,
     * but it is useful while developing and debugging M3.
     */
    print_hex("[M1] Original key: ",
              key,
              KEY_SIZE);


    print_hex("[M1] IV: ",
              iv,
              IV_SIZE);


    /*
     * ========================================
     * M1: Encrypt
     * ========================================
     */

    ciphertext_len = encrypt_gcm(plaintext,
                                 plaintext_len,
                                 key,
                                 iv,
                                 ciphertext,
                                 tag);

    if (ciphertext_len < 0)
    {
        fprintf(stderr,
                "Error: AES-GCM encryption failed\n");

        return EXIT_FAILURE;
    }


    print_hex("[M1] Ciphertext: ",
              ciphertext,
              ciphertext_len);


    print_hex("[M1] Authentication tag: ",
              tag,
              TAG_SIZE);


    /*
     * ========================================
     * M1: Decrypt
     * ========================================
     */

    decrypted_len = decrypt_gcm(ciphertext,
                                ciphertext_len,
                                tag,
                                key,
                                iv,
                                decrypted);

    if (decrypted_len < 0)
    {
        fprintf(stderr,
                "Error: AES-GCM decryption failed\n");

        return EXIT_FAILURE;
    }


    decrypted[decrypted_len] = '\0';


    printf("[M1] Decrypted plaintext: %s\n",
           decrypted);


    if (strcmp((const char *)plaintext,
               (const char *)decrypted) == 0)
    {
        printf("[M1] AES-256-GCM test: PASS\n");
    }
    else
    {
        printf("[M1] AES-256-GCM test: FAIL\n");
        return EXIT_FAILURE;
    }


    /*
     * ========================================
     * M2: Stack reconnaissance
     * ========================================
     */

    printf("\n========================================\n");
    printf("       M2 - Stack Reconnaissance\n");
    printf("========================================\n");


    printf("[M2] key   address: %p\n",
           (void *)key);

    printf("[M2] input address: %p\n",
           (void *)frame.input);

    printf("[M2] frame address: %p\n",
           (void *)&frame);

    printf("[M2] input size: %d bytes\n",
           BUFFER_SIZE);

    printf("[M2] key size: %d bytes\n",
           KEY_SIZE);


    /*
     * Copy the real AES key into the vulnerable
     * memory region immediately following input.
     *
     * This represents sensitive data residing next
     * to a buffer that is incorrectly handled.
     */
    memcpy(frame.exposed_key,
           key,
           KEY_SIZE);


    /*
     * ========================================
     * M3: Vulnerable information disclosure
     * ========================================
     */

    printf("\n========================================\n");
    printf("       M3 - Information Disclosure\n");
    printf("========================================\n");


    printf("[M3] Enter up to %d bytes of test data: ",
           BUFFER_SIZE);

    fflush(stdout);


    /*
     * Read at most 64 bytes into the input buffer.
     */
    ssize_t received =
        read(STDIN_FILENO,
             frame.input,
             BUFFER_SIZE);


    if (received < 0)
    {
        perror("[M3] read");
        return EXIT_FAILURE;
    }


    printf("\n[M3] Received %zd bytes.\n",
           received);


    /*
     * VULNERABILITY:
     *
     * frame.input is only 64 bytes.
     *
     * However, 96 bytes are read from frame.input:
     *
     *     64 bytes = legitimate input
     *     32 bytes = sensitive key data
     *
     * This is an out-of-bounds read / information leak.
     */
    printf("[M3] Leaked region (96 bytes): ");

    fflush(stdout);

    ssize_t leaked =
        write(STDOUT_FILENO,
              frame.input,
              BUFFER_SIZE + KEY_SIZE);


    if (leaked < 0)
    {
        perror("[M3] write");
        return EXIT_FAILURE;
    }


    printf("\n");


    /*
     * Print the leaked region separately in hexadecimal.
     *
     * This makes verification easier during the lab.
     */
    print_hex("[M3] Leak in hex: ",
              (unsigned char *)frame.input,
              BUFFER_SIZE + KEY_SIZE);


    /*
     * ========================================
     * M3 verification
     * ========================================
     */

    if (memcmp(frame.input + BUFFER_SIZE,
               key,
               KEY_SIZE) == 0)
    {
        printf("[M3] Key disclosure verification: PASS\n");
        printf("[M3] The leaked 32-byte region matches the AES key.\n");
    }
    else
    {
        printf("[M3] Key disclosure verification: FAIL\n");
    }


    printf("\n========================================\n");
    printf("       KeyLeak M1/M2/M3 Complete\n");
    printf("========================================\n");


    return EXIT_SUCCESS;
}
