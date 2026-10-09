#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define KEY_SIZE 32
#define IV_SIZE 12
#define TAG_SIZE 16
#define BUFFER_SIZE 64

/*
 * KeyLeak - M1: Vulnerable Target Application
 *
 * Current goals:
 * 1. Generate a random AES-256 key.
 * 2. Store the key in a stack buffer.
 * 3. Encrypt a sample plaintext using AES-256-GCM.
 * 4. Decrypt the ciphertext.
 * 5. Verify that the original plaintext is recovered.
 *
 * The vulnerable input path is intentionally kept separate
 * so that the cryptographic functionality can be verified first.
 */


/* Print bytes as hexadecimal */
void print_hex(const char *label, const unsigned char *data, int length)
{
    printf("%s", label);

    for (int i = 0; i < length; i++)
    {
        printf("%02x", data[i]);
    }

    printf("\n");
}


/*
 * AES-256-GCM encryption
 */
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

    /* Initialize AES-256-GCM */
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

    /* Set IV */
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

    /* Encrypt plaintext */
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

    /* Finalize encryption */
    if (EVP_EncryptFinal_ex(
            ctx,
            ciphertext + len,
            &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    ciphertext_len += len;

    /* Obtain authentication tag */
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


/*
 * AES-256-GCM decryption
 */
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

    /* Initialize AES-256-GCM */
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

    /* Set key and IV */
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

    /* Decrypt ciphertext */
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

    /*
     * Set the expected authentication tag.
     * GCM will verify it during EVP_DecryptFinal_ex().
     */
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
        &len
    );

    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0)
    {
        plaintext_len += len;
        return plaintext_len;
    }

    /* Authentication failed */
    return -1;
}


int main(void)
{
    /*
     * IMPORTANT FOR THE PROJECT:
     *
     * The AES key is deliberately declared as a local variable.
     * Therefore it resides in the function's stack frame.
     *
     * Later, M2/M3 will use this fact for the controlled
     * memory-safety demonstration.
     */
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

    printf("========================================\n");
    printf("       KeyLeak - M1 Vulnerable App\n");
    printf("========================================\n\n");

    /*
     * ----------------------------------------------------
     * STEP 1: Generate AES-256 key
     * ----------------------------------------------------
     */

    if (RAND_bytes(key, KEY_SIZE) != 1)
    {
        fprintf(stderr, "Error: RAND_bytes() failed\n");
        return EXIT_FAILURE;
    }

    /*
     * Generate a random 96-bit GCM IV.
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
     * For M1 verification we display the key.
     *
     * Later, when demonstrating the vulnerability,
     * this should be treated as the "known real key"
     * against which the recovered bytes are compared.
     */
    print_hex("[3] Original key: ", key, KEY_SIZE);

    print_hex("[4] IV: ", iv, IV_SIZE);

    /*
     * ----------------------------------------------------
     * STEP 2: Encrypt plaintext
     * ----------------------------------------------------
     */

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
        fprintf(stderr, "Error: encryption failed\n");
        return EXIT_FAILURE;
    }

    printf("\n[5] Encryption successful.\n");

    print_hex(
        "[6] Ciphertext: ",
        ciphertext,
        ciphertext_len
    );

    print_hex(
        "[7] Authentication tag: ",
        tag,
        TAG_SIZE
    );

    /*
     * ----------------------------------------------------
     * STEP 3: Decrypt ciphertext
     * ----------------------------------------------------
     */

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
        fprintf(stderr, "Error: decryption/authentication failed\n");
        return EXIT_FAILURE;
    }

    decrypted[decrypted_len] = '\0';

    printf("\n[8] Decryption successful.\n");
    printf("[9] Decrypted plaintext: %s\n", decrypted);

    /*
     * ----------------------------------------------------
     * STEP 4: Verify plaintext
     * ----------------------------------------------------
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
     * ----------------------------------------------------
     * TEMPORARY INPUT
     * ----------------------------------------------------
     *
     * For now we only accept bounded input.
     * This lets us verify that the application can interact
     * with the user without introducing the vulnerability yet.
     *
     * The deliberately unsafe input path will be introduced
     * after M1 + M3 preparation.
     */

    char input[BUFFER_SIZE];

    printf("\nEnter a test message: ");

    if (fgets(input, sizeof(input), stdin) != NULL)
    {
        input[strcspn(input, "\n")] = '\0';

        printf("Received: %s\n", input);
    }

    return EXIT_SUCCESS;
}
