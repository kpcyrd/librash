/* Copied from evp_digestinit(3) man page */

#include <stdio.h>
#include <string.h>

#ifdef NO_SHIM
#include <openssl/evp.h>
#else
#include "compat/evp.h"
#endif

int main(int argc, char *argv[])
{
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    char mess1[] = "Test Message\n";
    char mess2[] = "Hello World\n";
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len, i;

    if (argv[1] == NULL) {
        printf("Usage: mdtest digestname\n");
        exit(1);
    }

    md = EVP_get_digestbyname(argv[1]);
    if (md == NULL) {
        printf("Unknown message digest %s\n", argv[1]);
        exit(1);
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
       printf("Message digest create failed.\n");
       exit(1);
    }
    if (!EVP_DigestInit_ex2(mdctx, md, NULL)) {
        printf("Message digest initialization failed.\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }
    if (!EVP_DigestUpdate(mdctx, mess1, strlen(mess1))) {
        printf("Message digest update failed.\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }
    if (!EVP_DigestUpdate(mdctx, mess2, strlen(mess2))) {
        printf("Message digest update failed.\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }
    if (!EVP_DigestFinal_ex(mdctx, md_value, &md_len)) {
        printf("Message digest finalization failed.\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }
    EVP_MD_CTX_free(mdctx);

    printf("Digest is: ");
    for (i = 0; i < md_len; i++)
        printf("%02x", md_value[i]);
    printf("\n");

    exit(0);
}
