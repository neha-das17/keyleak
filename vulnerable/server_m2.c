#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define KEY_SIZE 32
#define IV_SIZE 12
#define TAG_SIZE 16
#define BUFFER_SIZE 64

void print_hex(const char *label, const unsigned char *data, int length)
{
    printf("%s", label);

    for (int i = 0; i < length; i++)
        printf("%02x", data[i]);

    printf("\n");
}

int encrypt_gcm(
    const unsigned char *plaintext,
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
        return -1;

    if (EVP_EncryptInit_ex(
            ctx,
            EVP_aes_256_gcm(),
            NULL,
            NULL,
            NULL) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptInit_ex(
            ctx,
            NULL,
            NULL,
            key,
            iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptUpdate(
            ctx,
            ciphertext,
            &len,
            plaintext,
            plaintext_len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(
            ctx,
            ciphertext + len,
            &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(
            ctx,
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

int decrypt_gcm(
    const unsigned char *ciphertext,
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
        return -1;

    if (EVP_DecryptInit_ex(
            ctx,
            EVP_aes_256_gcm(),
            NULL,
            NULL,
            NULL) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptInit_ex(
            ctx,
            NULL,
            NULL,
            key,
            iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptUpdate(
            ctx,
            plaintext,
            &len,
            ciphertext,
            ciphertext_len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_SET_TAG,
            TAG_SIZE,
            (void *)tag) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    ret = EVP_DecryptFinal_ex(
        ctx,
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

int main(void)
{
    /*
     * M1 cryptographic buffers.
     */
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    unsigned char tag[TAG_SIZE];
    unsigned char ciphertext[BUFFER_SIZE];
    unsigned char decrypted[BUFFER_SIZE];

    /*
     * M2/M3 deliberately vulnerable input buffer.
     *
     * This is kept separate from the cryptographic buffers so
     * that the original AES-GCM implementation remains intact.
     */
    char input[BUFFER_SIZE];

    const unsigned char plaintext[] =
        "Confidential KeyLeak message";

    int plaintext_len;
    int ciphertext_len;
    int decrypted_len;

    printf("========================================\n");
    printf("       KeyLeak - M1/M2/M3 App\n");
    printf("========================================\n\n");

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

    printf("[1] AES-256-GCM key generated successfully.\n");
    printf("[2] Key size: %d bytes (%d bits)\n",
           KEY_SIZE,
           KEY_SIZE * 8);

    /*
     * M1 reference output.
     *
     * Keep this while developing the project because it lets us
     * compare the leaked key against the real key.
     */
    print_hex(
        "[3] Original key: ",
        key,
        KEY_SIZE);

    print_hex(
        "[4] IV: ",
        iv,
        IV_SIZE);

    /*
     * AES-GCM encryption.
     */
    ciphertext_len = encrypt_gcm(
        plaintext,
        plaintext_len,
        key,
        iv,
        ciphertext,
        tag);

    if (ciphertext_len < 0)
    {
        fprintf(stderr, "Error: encryption failed\n");
        return EXIT_FAILURE;
    }

    printf("\n[5] Encryption successful.\n");

    print_hex(
        "[6] Ciphertext: ",
        ciphertext,
        ciphertext_len);

    print_hex(
        "[7] Authentication tag: ",
        tag,
        TAG_SIZE);

    /*
     * AES-GCM decryption.
     */
    decrypted_len = decrypt_gcm(
        ciphertext,
        ciphertext_len,
        tag,
        key,
        iv,
        decrypted);

    if (decrypted_len < 0)
    {
        fprintf(
            stderr,
            "Error: decryption/authentication failed\n");

        return EXIT_FAILURE;
    }

    decrypted[decrypted_len] = '\0';

    printf("\n[8] Decryption successful.\n");
    printf(
        "[9] Decrypted plaintext: %s\n",
        decrypted);

    /*
     * M1 verification.
     */
    if (strcmp(
            (const char *)plaintext,
            (const char *)decrypted) == 0)
    {
        printf("\n========================================\n");
        printf("M1 STATUS: PASS\n");
        printf("AES-256-GCM encryption/decryption works.\n");
        printf("========================================\n");
    }
    else
    {
        printf("\n========================================\n");
        printf("M1 STATUS: FAIL\n");
        printf("Plaintext mismatch.\n");
        printf("========================================\n");

        return EXIT_FAILURE;
    }

    /*
     * ==========================================================
     * M2 / M3 VULNERABLE INPUT SECTION
     * ==========================================================
     *
     * IMPORTANT:
     *
     * The current fgets() version is the safe M1 implementation.
     *
     * For the vulnerability demonstration we intentionally use
     * read() with BUFFER_SIZE bytes and then treat the resulting
     * buffer as a C string.
     *
     * This demonstrates the difference between a bounded read
     * and an unsafe string interpretation.
     */

    printf("\n[M2] Vulnerable input demonstration\n");
    printf("Enter up to 64 bytes: ");

    ssize_t n = read(
        STDIN_FILENO,
        input,
        sizeof(input));

    if (n < 0)
    {
        perror("read");
        return EXIT_FAILURE;
    }

    /*
     * Deliberately do NOT append a '\0' here.
     *
     * This is the vulnerable condition that M3 will investigate.
     *
     * printf("%s") expects a null-terminated string, but the
     * buffer may contain no terminating null byte.
     */
    printf("[M3] Received: %s\n", input);

    return EXIT_SUCCESS;
}
