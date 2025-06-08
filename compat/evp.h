#include <librash/hash.h>

#define EVP_MD_CTX RashCtx
#define EVP_MD RashDigest

#define EVP_MAX_MD_SIZE RASH_MAX_DIGEST_SIZE

#define EVP_get_digestbyname rash_digestbyname
#define EVP_MD_CTX_new rash_ctx_new
#define EVP_DigestInit_ex rash_digest_init
#define EVP_DigestUpdate rash_digest_update
#define EVP_DigestFinal_ex rash_digest_final
#define EVP_MD_CTX_free rash_ctx_free

/* legacy calls */
#define EVP_MD_CTX_create()     EVP_MD_CTX_new()
#define EVP_MD_CTX_init(ctx)    EVP_MD_CTX_reset((ctx))
#define EVP_MD_CTX_destroy(ctx) EVP_MD_CTX_free((ctx))

#define OpenSSL_add_all_digests()
