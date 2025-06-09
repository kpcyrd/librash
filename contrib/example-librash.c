#include <stdio.h>
#include <string.h>
#include <librash/hash.h>

int main(int argc, char *argv[]) {
    RashCtx *mdctx;
    const RashDigest *md;

    char mess1[] = "Test Message\n";
    char mess2[] = "Hello World\n";
    unsigned char md_value[RASH_MAX_DIGEST_SIZE];
    unsigned int md_len, i;

    if(!argv[1]) {
           printf("Usage: mdtest digestname\n");
           exit(1);
    }

    md = rash_digestbyname(argv[1]);

    if(!md) {
           printf("Unknown message digest %s\n", argv[1]);
           exit(1);
    }

    mdctx = rash_ctx_new();
    rash_digest_init(mdctx, md, NULL);
    rash_digest_update(mdctx, mess1, strlen(mess1));
    rash_digest_update(mdctx, mess2, strlen(mess2));
    rash_digest_final(mdctx, md_value, &md_len);
    rash_ctx_free(mdctx);

    printf("Digest is: ");
    for(i = 0; i < md_len; i++)
        printf("%02x", md_value[i]);
    printf("\n");

    return 0;
}
