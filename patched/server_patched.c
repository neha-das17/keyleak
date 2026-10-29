#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#define KEY_SIZE     32
#define IV_SIZE      12
#define TAG_SIZE     16
#define BUFFER_SIZE  64

/* -------------------------------------------------------
   Print hexadecimal bytes
   ------------------------------------------------------- */

void print_hex(const char *label,
               const unsigned char *data,
               int length)
{
    printf("%s", label);

    for (int i = 0; i < length; i++)
    {
        printf("%02x", data[i]);
    }

    printf("\n");
}

/* -------------------------------------------------------
   M5: Safe input handling

   Accept at most 64 bytes.
   Reject oversized input.
   ------------------------------------------------------- */

int read_safe_input(unsigned char *buffer, size_t capacity)
{
    size_t count = 0;
    unsigned char ch;
    ssize_t result;

    while (1)
    {
        result = read(STDIN_FILENO, &ch, 1);

        if (result < 0)
        {
            perror("read");
            return -1;
        }

        if (result == 0 || ch == '\n')
        {
            break;
        }

        if (count >= capacity)
        {
            /* Discard remaining input */
            while (ch != '\n')
            {
                result = read(STDIN_FILENO, &ch, 1);

                if (result <= 0)
                    break;
            }

            return -2;
        }

        buffer[count++] = ch;
    }

    return (int)count;
}

/* -------------------------------------------------------
   AES-256-GCM Encryption
   ------------------------------------------------------- */

int encrypt_gcm(const unsigned char *plaintext,
                int plaintext_len,
                const unsigned char *key,
                const unsigned char *iv,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx = NULL;

    int len = 0;
    int ciphertext_len = 0;
    int success = 0;

    ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL)
        return -1;

    if (EVP_EncryptInit_ex(ctx,
                           EVP_aes_256_gcm(),
                           NULL,
                           NULL,
                           NULL) != 1)
        goto cleanup;

    if (EVP_EncryptInit_ex(ctx,
                           NULL,
                           NULL,
                           key,
                           iv) != 1)
        goto cleanup;

    if (EVP_EncryptUpdate(ctx,
                          ciphertext,
                          &len,
                          plaintext,
                          plaintext_len) != 1)
        goto cleanup;

    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx,
                            ciphertext + ciphertext_len,
                            &len) != 1)
        goto cleanup;

    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx,
                            EVP_CTRL_GCM_GET_TAG,
                            TAG_SIZE,
                            tag) != 1)
        goto cleanup;

    success = 1;

cleanup:

    EVP_CIPHER_CTX_free(ctx);

    if (!success)
        return -1;

    return ciphertext_len;
}

/* -------------------------------------------------------
   AES-256-GCM Decryption
   ------------------------------------------------------- */

int decrypt_gcm(const unsigned char *ciphertext,
                int ciphertext_len,
                const unsigned char *tag,
                const unsigned char *key,
                const unsigned char *iv,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = NULL;

    int len = 0;
    int plaintext_len = 0;
    int ret = 0;
    int success = 0;

    ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL)
        return -1;

    if (EVP_DecryptInit_ex(ctx,
                           EVP_aes_256_gcm(),
                           NULL,
                           NULL,
                           NULL) != 1)
        goto cleanup;

    if (EVP_DecryptInit_ex(ctx,
                           NULL,
                           NULL,
                           key,
                           iv) != 1)
        goto cleanup;

    if (EVP_DecryptUpdate(ctx,
                          plaintext,
                          &len,
                          ciphertext,
                          ciphertext_len) != 1)
        goto cleanup;

    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx,
                            EVP_CTRL_GCM_SET_TAG,
                            TAG_SIZE,
                            (void *)tag) != 1)
        goto cleanup;

    ret = EVP_DecryptFinal_ex(ctx,
                              plaintext + plaintext_len,
                              &len);

    if (ret <= 0)
        goto cleanup;

    plaintext_len += len;
    success = 1;

cleanup:

    EVP_CIPHER_CTX_free(ctx);

    if (!success)
        return -1;

    return plaintext_len;
}

/* -------------------------------------------------------
   M5: Secure memory zeroization
   ------------------------------------------------------- */

void secure_zeroize(void *buffer, size_t length)
{
    OPENSSL_cleanse(buffer, length);
}

/* -------------------------------------------------------
   M5: Main Patched Application
   ------------------------------------------------------- */

int main(void)
{
    unsigned char key[KEY_SIZE] = {0};
    unsigned char iv[IV_SIZE] = {0};
    unsigned char tag[TAG_SIZE] = {0};

    unsigned char ciphertext[BUFFER_SIZE] = {0};
    unsigned char decrypted[BUFFER_SIZE + 1] = {0};

    unsigned char input[BUFFER_SIZE] = {0};

    const unsigned char plaintext[] =
        "Confidential KeyLeak message";

    int plaintext_len;
    int ciphertext_len;
    int decrypted_len;
    int received;

    int status = EXIT_FAILURE;

    printf("========================================\n");
    printf("       KeyLeak - M5 Patched App\n");
    printf("========================================\n\n");

    /* -----------------------------------------
       M1: Generate AES-256 key
       ----------------------------------------- */

    if (RAND_bytes(key, KEY_SIZE) != 1)
    {
        fprintf(stderr, "[M5] Key generation failed.\n");
        goto cleanup;
    }

    if (RAND_bytes(iv, IV_SIZE) != 1)
    {
        fprintf(stderr, "[M5] IV generation failed.\n");
        goto cleanup;
    }

    printf("[M5] AES-256-GCM key generated successfully.\n");
    printf("[M5] Key size: 32 bytes (256 bits)\n");

    /* Never print the encryption key. */

    plaintext_len = (int)strlen((const char *)plaintext);

    /* -----------------------------------------
       AES-256-GCM Encryption
       ----------------------------------------- */

    ciphertext_len = encrypt_gcm(
        plaintext,
        plaintext_len,
        key,
        iv,
        ciphertext,
        tag
    );

    if (ciphertext_len < 0)
    {
        fprintf(stderr, "[M5] Encryption failed.\n");
        goto cleanup;
    }

    print_hex("[M5] IV: ", iv, IV_SIZE);

    print_hex("[M5] Ciphertext: ",
              ciphertext,
              ciphertext_len);

    print_hex("[M5] Authentication tag: ",
              tag,
              TAG_SIZE);

    /* -----------------------------------------
       AES-256-GCM Decryption
       ----------------------------------------- */

    decrypted_len = decrypt_gcm(
        ciphertext,
        ciphertext_len,
        tag,
        key,
        iv,
        decrypted
    );

    if (decrypted_len < 0)
    {
        fprintf(stderr,
                "[M5] AES-GCM authentication failed.\n");

        goto cleanup;
    }

    decrypted[decrypted_len] = '\0';

    printf("\n[M5] Decrypted plaintext: %s\n",
           decrypted);

    if (decrypted_len != plaintext_len ||
        memcmp(plaintext, decrypted,
               (size_t)plaintext_len) != 0)
    {
        printf("[M5] AES-GCM self-test: FAIL\n");
        goto cleanup;
    }

    printf("[M5] AES-GCM self-test: PASS\n");

    /* -----------------------------------------
       M5: Bounds-checked input
       ----------------------------------------- */

    printf("\n========================================\n");
    printf("       M5 - Secure Input Handling\n");
    printf("========================================\n");

    printf("[M5] Enter input (maximum %d bytes): ",
           BUFFER_SIZE);

    fflush(stdout);

    received = read_safe_input(input, BUFFER_SIZE);

    if (received == -2)
    {
        printf("\n[M5] Input rejected: exceeds %d bytes.\n",
               BUFFER_SIZE);

        status = EXIT_FAILURE;
        goto cleanup;
    }

    if (received < 0)
    {
        fprintf(stderr, "\n[M5] Input read failed.\n");
        goto cleanup;
    }

    printf("\n[M5] Accepted %d input bytes\n",
           received);

    /* Print only the actual input bytes. */

    print_hex(
        "[M5] Input in hex: ",
        input,
        received
    );

    printf("[M5] No adjacent memory disclosed\n");

    /* -----------------------------------------
       Successful execution
       ----------------------------------------- */

    status = EXIT_SUCCESS;

cleanup:

    /* -----------------------------------------
       M5: Secure Zeroization
       ----------------------------------------- */

    secure_zeroize(key, sizeof(key));
    secure_zeroize(iv, sizeof(iv));
    secure_zeroize(tag, sizeof(tag));

    secure_zeroize(ciphertext, sizeof(ciphertext));
    secure_zeroize(decrypted, sizeof(decrypted));
    secure_zeroize(input, sizeof(input));

    printf("[M5] Sensitive buffers cleansed\n");

    printf("\n========================================\n");
    printf("       KeyLeak M5 Complete\n");
    printf("========================================\n");

    return status;
}
