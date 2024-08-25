/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_CORE_NUMBERS_H
# define ossl_OPENSSL_CORE_NUMBERS_H
# pragma once

# include <stdarg.h>
# include "ossl/openssl/core.h"

# ifdef __cplusplus
extern "C" {
# endif

/*-
 * Identities
 * ----------
 *
 * All series start with 1, to allow 0 to be an array terminator.
 * For any FUNC identity, we also provide a function signature typedef
 * and a static inline function to extract a function pointer from a
 * ossl_OSSL_DISPATCH element in a type safe manner.
 *
 * Names:
 * for any function base name 'foo' (uppercase form 'FOO'), we will have
 * the following:
 * - a macro for the identity with the name OSSL_FUNC_'FOO' or derivatives
 *   thereof (to be specified further down)
 * - a function signature typedef with the name OSSL_FUNC_'foo'_fn
 * - a function pointer extractor function with the name OSSL_FUNC_'foo'
 */

/*
 * Helper macro to create the function signature typedef and the extractor
 * |type| is the return-type of the function, |name| is the name of the
 * function to fetch, and |args| is a parenthesized list of parameters
 * for the function (that is, it is |name|'s function signature).
 * Note: This is considered a "reserved" internal macro. Applications should
 * not use this or assume its existence.
 */
#define ossl_OSSL_CORE_MAKE_FUNC(type,name,args)                             \
    typedef type (OSSL_FUNC_##name##_fn)args;                           \
    static ossl_ossl_unused ossl_ossl_inline \
    OSSL_FUNC_##name##_fn *OSSL_FUNC_##name(const ossl_OSSL_DISPATCH *opf)   \
    {                                                                   \
        return (OSSL_FUNC_##name##_fn *)opf->function;                  \
    }

/*
 * Core function identities, for the two ossl_OSSL_DISPATCH tables being passed
 * in the ossl_OSSL_provider_init call.
 *
 * 0 serves as a marker for the end of the ossl_OSSL_DISPATCH array, and must
 * therefore NEVER be used as a function identity.
 */
/* Functions provided by the Core to the provider, reserved numbers 1-1023 */
# define ossl_OSSL_FUNC_CORE_GETTABLE_PARAMS        1
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *,
                    core_gettable_params,(const ossl_OSSL_CORE_HANDLE *prov))
# define ossl_OSSL_FUNC_CORE_GET_PARAMS             2
ossl_OSSL_CORE_MAKE_FUNC(int,core_get_params,(const ossl_OSSL_CORE_HANDLE *prov,
                                         ossl_OSSL_PARAM params[]))
# define ossl_OSSL_FUNC_CORE_THREAD_START           3
ossl_OSSL_CORE_MAKE_FUNC(int,core_thread_start,(const ossl_OSSL_CORE_HANDLE *prov,
                                           ossl_OSSL_thread_stop_handler_fn handfn,
                                           void *arg))
# define ossl_OSSL_FUNC_CORE_GET_LIBCTX             4
ossl_OSSL_CORE_MAKE_FUNC(ossl_OPENSSL_CORE_CTX *,core_get_libctx,
                    (const ossl_OSSL_CORE_HANDLE *prov))
# define ossl_OSSL_FUNC_CORE_NEW_ERROR              5
ossl_OSSL_CORE_MAKE_FUNC(void,core_new_error,(const ossl_OSSL_CORE_HANDLE *prov))
# define ossl_OSSL_FUNC_CORE_SET_ERROR_DEBUG        6
ossl_OSSL_CORE_MAKE_FUNC(void,core_set_error_debug,
                    (const ossl_OSSL_CORE_HANDLE *prov,
                     const char *file, int line, const char *func))
# define ossl_OSSL_FUNC_CORE_VSET_ERROR             7
ossl_OSSL_CORE_MAKE_FUNC(void,core_vset_error,
                    (const ossl_OSSL_CORE_HANDLE *prov,
                     uint32_t reason, const char *fmt, va_list args))
# define ossl_OSSL_FUNC_CORE_SET_ERROR_MARK         8
ossl_OSSL_CORE_MAKE_FUNC(int, core_set_error_mark, (const ossl_OSSL_CORE_HANDLE *prov))
# define ossl_OSSL_FUNC_CORE_CLEAR_LAST_ERROR_MARK  9
ossl_OSSL_CORE_MAKE_FUNC(int, core_clear_last_error_mark,
                    (const ossl_OSSL_CORE_HANDLE *prov))
# define ossl_OSSL_FUNC_CORE_POP_ERROR_TO_MARK     10
ossl_OSSL_CORE_MAKE_FUNC(int, core_pop_error_to_mark, (const ossl_OSSL_CORE_HANDLE *prov))


/* Functions to access the OBJ database */

#define ossl_OSSL_FUNC_CORE_OBJ_ADD_SIGID          11
#define ossl_OSSL_FUNC_CORE_OBJ_CREATE             12

ossl_OSSL_CORE_MAKE_FUNC(int, core_obj_add_sigid,
                    (const ossl_OSSL_CORE_HANDLE *prov, const char  *sign_name,
                     const char *digest_name, const char *pkey_name))
ossl_OSSL_CORE_MAKE_FUNC(int, core_obj_create,
                    (const ossl_OSSL_CORE_HANDLE *prov, const char *oid,
                     const char *sn, const char *ln))

/* Memory allocation, freeing, clearing. */
#define ossl_OSSL_FUNC_CRYPTO_MALLOC               20
ossl_OSSL_CORE_MAKE_FUNC(void *,
        ossl_CRYPTO_malloc, (size_t num, const char *file, int line))
#define ossl_OSSL_FUNC_CRYPTO_ZALLOC               21
ossl_OSSL_CORE_MAKE_FUNC(void *,
        ossl_CRYPTO_zalloc, (size_t num, const char *file, int line))
#define ossl_OSSL_FUNC_CRYPTO_FREE                 22
ossl_OSSL_CORE_MAKE_FUNC(void,
        ossl_CRYPTO_free, (void *ptr, const char *file, int line))
#define ossl_OSSL_FUNC_CRYPTO_CLEAR_FREE           23
ossl_OSSL_CORE_MAKE_FUNC(void,
        ossl_CRYPTO_clear_free, (void *ptr, size_t num, const char *file, int line))
#define ossl_OSSL_FUNC_CRYPTO_REALLOC              24
ossl_OSSL_CORE_MAKE_FUNC(void *,
        ossl_CRYPTO_realloc, (void *addr, size_t num, const char *file, int line))
#define ossl_OSSL_FUNC_CRYPTO_CLEAR_REALLOC        25
ossl_OSSL_CORE_MAKE_FUNC(void *,
        ossl_CRYPTO_clear_realloc, (void *addr, size_t old_num, size_t num,
                               const char *file, int line))
#define ossl_OSSL_FUNC_CRYPTO_SECURE_MALLOC        26
ossl_OSSL_CORE_MAKE_FUNC(void *,
        ossl_CRYPTO_secure_malloc, (size_t num, const char *file, int line))
#define ossl_OSSL_FUNC_CRYPTO_SECURE_ZALLOC        27
ossl_OSSL_CORE_MAKE_FUNC(void *,
        ossl_CRYPTO_secure_zalloc, (size_t num, const char *file, int line))
#define ossl_OSSL_FUNC_CRYPTO_SECURE_FREE          28
ossl_OSSL_CORE_MAKE_FUNC(void,
        ossl_CRYPTO_secure_free, (void *ptr, const char *file, int line))
#define ossl_OSSL_FUNC_CRYPTO_SECURE_CLEAR_FREE    29
ossl_OSSL_CORE_MAKE_FUNC(void,
        ossl_CRYPTO_secure_clear_free, (void *ptr, size_t num, const char *file,
                                   int line))
#define ossl_OSSL_FUNC_CRYPTO_SECURE_ALLOCATED     30
ossl_OSSL_CORE_MAKE_FUNC(int,
        ossl_CRYPTO_secure_allocated, (const void *ptr))
#define ossl_OSSL_FUNC_OPENSSL_CLEANSE             31
ossl_OSSL_CORE_MAKE_FUNC(void,
        ossl_OPENSSL_cleanse, (void *ptr, size_t len))

/* Bio functions provided by the core */
#define ossl_OSSL_FUNC_BIO_NEW_FILE                40
#define ossl_OSSL_FUNC_BIO_NEW_MEMBUF              41
#define ossl_OSSL_FUNC_BIO_READ_EX                 42
#define ossl_OSSL_FUNC_BIO_WRITE_EX                43
#define ossl_OSSL_FUNC_BIO_UP_REF                  44
#define ossl_OSSL_FUNC_BIO_FREE                    45
#define ossl_OSSL_FUNC_BIO_VPRINTF                 46
#define ossl_OSSL_FUNC_BIO_VSNPRINTF               47
#define ossl_OSSL_FUNC_BIO_PUTS                    48
#define ossl_OSSL_FUNC_BIO_GETS                    49
#define ossl_OSSL_FUNC_BIO_CTRL                    50


ossl_OSSL_CORE_MAKE_FUNC(ossl_OSSL_CORE_BIO *, ossl_BIO_new_file, (const char *filename,
                                                    const char *mode))
ossl_OSSL_CORE_MAKE_FUNC(ossl_OSSL_CORE_BIO *, BIO_new_membuf, (const void *buf, int len))
ossl_OSSL_CORE_MAKE_FUNC(int, ossl_BIO_read_ex, (ossl_OSSL_CORE_BIO *bio, void *data,
                                       size_t data_len, size_t *bytes_read))
ossl_OSSL_CORE_MAKE_FUNC(int, ossl_BIO_write_ex, (ossl_OSSL_CORE_BIO *bio, const void *data,
                                        size_t data_len, size_t *written))
ossl_OSSL_CORE_MAKE_FUNC(int, ossl_BIO_gets, (ossl_OSSL_CORE_BIO *bio, char *buf, int size))
ossl_OSSL_CORE_MAKE_FUNC(int, ossl_BIO_puts, (ossl_OSSL_CORE_BIO *bio, const char *str))
ossl_OSSL_CORE_MAKE_FUNC(int, ossl_BIO_up_ref, (ossl_OSSL_CORE_BIO *bio))
ossl_OSSL_CORE_MAKE_FUNC(int, ossl_BIO_free, (ossl_OSSL_CORE_BIO *bio))
ossl_OSSL_CORE_MAKE_FUNC(int, ossl_BIO_vprintf, (ossl_OSSL_CORE_BIO *bio, const char *format,
                                       va_list args))
ossl_OSSL_CORE_MAKE_FUNC(int, ossl_BIO_vsnprintf,
                   (char *buf, size_t n, const char *fmt, va_list args))
ossl_OSSL_CORE_MAKE_FUNC(int, ossl_BIO_ctrl, (ossl_OSSL_CORE_BIO *bio,
                                    int cmd, long num, void *ptr))

#define ossl_OSSL_FUNC_SELF_TEST_CB               100
ossl_OSSL_CORE_MAKE_FUNC(void, self_test_cb, (ossl_OPENSSL_CORE_CTX *ctx, ossl_OSSL_CALLBACK **cb,
                                         void **cbarg))

/* Functions to get seed material from the operating system */
#define ossl_OSSL_FUNC_GET_ENTROPY                101
#define ossl_OSSL_FUNC_CLEANUP_ENTROPY            102
#define ossl_OSSL_FUNC_GET_NONCE                  103
#define ossl_OSSL_FUNC_CLEANUP_NONCE              104
ossl_OSSL_CORE_MAKE_FUNC(size_t, get_entropy, (const ossl_OSSL_CORE_HANDLE *handle,
                                          unsigned char **pout, int entropy,
                                          size_t min_len, size_t max_len))
ossl_OSSL_CORE_MAKE_FUNC(void, cleanup_entropy, (const ossl_OSSL_CORE_HANDLE *handle,
                                            unsigned char *buf, size_t len))
ossl_OSSL_CORE_MAKE_FUNC(size_t, get_nonce, (const ossl_OSSL_CORE_HANDLE *handle,
                                        unsigned char **pout, size_t min_len,
                                        size_t max_len, const void *salt,
                                        size_t salt_len))
ossl_OSSL_CORE_MAKE_FUNC(void, cleanup_nonce, (const ossl_OSSL_CORE_HANDLE *handle,
                                          unsigned char *buf, size_t len))

/* Functions to access the core's providers */
#define ossl_OSSL_FUNC_PROVIDER_REGISTER_CHILD_CB   105
#define ossl_OSSL_FUNC_PROVIDER_DEREGISTER_CHILD_CB 106
#define ossl_OSSL_FUNC_PROVIDER_NAME                107
#define ossl_OSSL_FUNC_PROVIDER_GET0_PROVIDER_CTX   108
#define ossl_OSSL_FUNC_PROVIDER_GET0_DISPATCH       109
#define ossl_OSSL_FUNC_PROVIDER_UP_REF              110
#define ossl_OSSL_FUNC_PROVIDER_FREE                111

ossl_OSSL_CORE_MAKE_FUNC(int, provider_register_child_cb,
                    (const ossl_OSSL_CORE_HANDLE *handle,
                     int (*create_cb)(const ossl_OSSL_CORE_HANDLE *provider, void *cbdata),
                     int (*remove_cb)(const ossl_OSSL_CORE_HANDLE *provider, void *cbdata),
                     int (*global_props_cb)(const char *props, void *cbdata),
                     void *cbdata))
ossl_OSSL_CORE_MAKE_FUNC(void, provider_deregister_child_cb,
                    (const ossl_OSSL_CORE_HANDLE *handle))
ossl_OSSL_CORE_MAKE_FUNC(const char *, provider_name,
                    (const ossl_OSSL_CORE_HANDLE *prov))
ossl_OSSL_CORE_MAKE_FUNC(void *, provider_get0_provider_ctx,
                    (const ossl_OSSL_CORE_HANDLE *prov))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_DISPATCH *, provider_get0_dispatch,
                    (const ossl_OSSL_CORE_HANDLE *prov))
ossl_OSSL_CORE_MAKE_FUNC(int, provider_up_ref,
                    (const ossl_OSSL_CORE_HANDLE *prov, int activate))
ossl_OSSL_CORE_MAKE_FUNC(int, provider_free,
                    (const ossl_OSSL_CORE_HANDLE *prov, int deactivate))

/* Functions provided by the provider to the Core, reserved numbers 1024-1535 */
# define ossl_OSSL_FUNC_PROVIDER_TEARDOWN           1024
ossl_OSSL_CORE_MAKE_FUNC(void,provider_teardown,(void *provctx))
# define ossl_OSSL_FUNC_PROVIDER_GETTABLE_PARAMS    1025
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *,
                    provider_gettable_params,(void *provctx))
# define ossl_OSSL_FUNC_PROVIDER_GET_PARAMS         1026
ossl_OSSL_CORE_MAKE_FUNC(int,provider_get_params,(void *provctx,
                                             ossl_OSSL_PARAM params[]))
# define ossl_OSSL_FUNC_PROVIDER_QUERY_OPERATION    1027
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_ALGORITHM *,provider_query_operation,
                    (void *provctx, int operation_id, int *no_store))
# define ossl_OSSL_FUNC_PROVIDER_UNQUERY_OPERATION  1028
ossl_OSSL_CORE_MAKE_FUNC(void, provider_unquery_operation,
                    (void *provctx, int operation_id, const ossl_OSSL_ALGORITHM *))
# define ossl_OSSL_FUNC_PROVIDER_GET_REASON_STRINGS 1029
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_ITEM *,provider_get_reason_strings,
                    (void *provctx))
# define ossl_OSSL_FUNC_PROVIDER_GET_CAPABILITIES   1030
ossl_OSSL_CORE_MAKE_FUNC(int, provider_get_capabilities, (void *provctx,
                    const char *capability, ossl_OSSL_CALLBACK *cb, void *arg))
# define ossl_OSSL_FUNC_PROVIDER_SELF_TEST          1031
ossl_OSSL_CORE_MAKE_FUNC(int, provider_self_test, (void *provctx))

/* Operations */

# define ossl_OSSL_OP_DIGEST                              1
# define ossl_OSSL_OP_CIPHER                              2   /* Symmetric Ciphers */
# define ossl_OSSL_OP_MAC                                 3
# define ossl_OSSL_OP_KDF                                 4
# define ossl_OSSL_OP_RAND                                5
# define ossl_OSSL_OP_KEYMGMT                            10
# define ossl_OSSL_OP_KEYEXCH                            11
# define ossl_OSSL_OP_SIGNATURE                          12
# define ossl_OSSL_OP_ASYM_CIPHER                        13
# define ossl_OSSL_OP_KEM                                14
/* New section for non-EVP operations */
# define ossl_OSSL_OP_ENCODER                            20
# define ossl_OSSL_OP_DECODER                            21
# define ossl_OSSL_OP_STORE                              22
/* Highest known operation number */
# define ossl_OSSL_OP__HIGHEST                           22

/* Digests */

# define ossl_OSSL_FUNC_DIGEST_NEWCTX                     1
# define ossl_OSSL_FUNC_DIGEST_INIT                       2
# define ossl_OSSL_FUNC_DIGEST_UPDATE                     3
# define ossl_OSSL_FUNC_DIGEST_FINAL                      4
# define ossl_OSSL_FUNC_DIGEST_DIGEST                     5
# define ossl_OSSL_FUNC_DIGEST_FREECTX                    6
# define ossl_OSSL_FUNC_DIGEST_DUPCTX                     7
# define ossl_OSSL_FUNC_DIGEST_GET_PARAMS                 8
# define ossl_OSSL_FUNC_DIGEST_SET_CTX_PARAMS             9
# define ossl_OSSL_FUNC_DIGEST_GET_CTX_PARAMS            10
# define ossl_OSSL_FUNC_DIGEST_GETTABLE_PARAMS           11
# define ossl_OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS       12
# define ossl_OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS       13

ossl_OSSL_CORE_MAKE_FUNC(void *, digest_newctx, (void *provctx))
ossl_OSSL_CORE_MAKE_FUNC(int, digest_init, (void *dctx, const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(int, digest_update,
                    (void *dctx, const unsigned char *in, size_t inl))
ossl_OSSL_CORE_MAKE_FUNC(int, digest_final,
                    (void *dctx,
                     unsigned char *out, size_t *outl, size_t outsz))
ossl_OSSL_CORE_MAKE_FUNC(int, digest_digest,
                    (void *provctx, const unsigned char *in, size_t inl,
                     unsigned char *out, size_t *outl, size_t outsz))

ossl_OSSL_CORE_MAKE_FUNC(void, digest_freectx, (void *dctx))
ossl_OSSL_CORE_MAKE_FUNC(void *, digest_dupctx, (void *dctx))

ossl_OSSL_CORE_MAKE_FUNC(int, digest_get_params, (ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(int, digest_set_ctx_params,
                    (void *vctx, const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(int, digest_get_ctx_params,
                    (void *vctx, ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *, digest_gettable_params,
                    (void *provctx))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *, digest_settable_ctx_params,
                    (void *dctx, void *provctx))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *, digest_gettable_ctx_params,
                    (void *dctx, void *provctx))

/* Symmetric Ciphers */

# define ossl_OSSL_FUNC_CIPHER_NEWCTX                     1
# define ossl_OSSL_FUNC_CIPHER_ENCRYPT_INIT               2
# define ossl_OSSL_FUNC_CIPHER_DECRYPT_INIT               3
# define ossl_OSSL_FUNC_CIPHER_UPDATE                     4
# define ossl_OSSL_FUNC_CIPHER_FINAL                      5
# define ossl_OSSL_FUNC_CIPHER_CIPHER                     6
# define ossl_OSSL_FUNC_CIPHER_FREECTX                    7
# define ossl_OSSL_FUNC_CIPHER_DUPCTX                     8
# define ossl_OSSL_FUNC_CIPHER_GET_PARAMS                 9
# define ossl_OSSL_FUNC_CIPHER_GET_CTX_PARAMS            10
# define ossl_OSSL_FUNC_CIPHER_SET_CTX_PARAMS            11
# define ossl_OSSL_FUNC_CIPHER_GETTABLE_PARAMS           12
# define ossl_OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS       13
# define ossl_OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS       14

ossl_OSSL_CORE_MAKE_FUNC(void *, cipher_newctx, (void *provctx))
ossl_OSSL_CORE_MAKE_FUNC(int, cipher_encrypt_init, (void *cctx,
                                                  const unsigned char *key,
                                                  size_t keylen,
                                                  const unsigned char *iv,
                                                  size_t ivlen,
                                                  const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(int, cipher_decrypt_init, (void *cctx,
                                                  const unsigned char *key,
                                                  size_t keylen,
                                                  const unsigned char *iv,
                                                  size_t ivlen,
                                                  const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(int, cipher_update,
                    (void *cctx,
                     unsigned char *out, size_t *outl, size_t outsize,
                     const unsigned char *in, size_t inl))
ossl_OSSL_CORE_MAKE_FUNC(int, cipher_final,
                    (void *cctx,
                     unsigned char *out, size_t *outl, size_t outsize))
ossl_OSSL_CORE_MAKE_FUNC(int, cipher_cipher,
                    (void *cctx,
                     unsigned char *out, size_t *outl, size_t outsize,
                     const unsigned char *in, size_t inl))
ossl_OSSL_CORE_MAKE_FUNC(void, cipher_freectx, (void *cctx))
ossl_OSSL_CORE_MAKE_FUNC(void *, cipher_dupctx, (void *cctx))
ossl_OSSL_CORE_MAKE_FUNC(int, cipher_get_params, (ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(int, cipher_get_ctx_params, (void *cctx,
                                                    ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(int, cipher_set_ctx_params, (void *cctx,
                                                    const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *, cipher_gettable_params,
                    (void *provctx))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *, cipher_settable_ctx_params,
                    (void *cctx, void *provctx))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *, cipher_gettable_ctx_params,
                    (void *cctx, void *provctx))

/* MACs */

# define ossl_OSSL_FUNC_MAC_NEWCTX                        1
# define ossl_OSSL_FUNC_MAC_DUPCTX                        2
# define ossl_OSSL_FUNC_MAC_FREECTX                       3
# define ossl_OSSL_FUNC_MAC_INIT                          4
# define ossl_OSSL_FUNC_MAC_UPDATE                        5
# define ossl_OSSL_FUNC_MAC_FINAL                         6
# define ossl_OSSL_FUNC_MAC_GET_PARAMS                    7
# define ossl_OSSL_FUNC_MAC_GET_CTX_PARAMS                8
# define ossl_OSSL_FUNC_MAC_SET_CTX_PARAMS                9
# define ossl_OSSL_FUNC_MAC_GETTABLE_PARAMS              10
# define ossl_OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS          11
# define ossl_OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS          12

ossl_OSSL_CORE_MAKE_FUNC(void *, mac_newctx, (void *provctx))
ossl_OSSL_CORE_MAKE_FUNC(void *, mac_dupctx, (void *src))
ossl_OSSL_CORE_MAKE_FUNC(void, mac_freectx, (void *mctx))
ossl_OSSL_CORE_MAKE_FUNC(int, mac_init, (void *mctx, const unsigned char *key,
                                    size_t keylen, const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(int, mac_update,
                    (void *mctx, const unsigned char *in, size_t inl))
ossl_OSSL_CORE_MAKE_FUNC(int, mac_final,
                    (void *mctx,
                     unsigned char *out, size_t *outl, size_t outsize))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *, mac_gettable_params, (void *provctx))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *, mac_gettable_ctx_params,
                    (void *mctx, void *provctx))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *, mac_settable_ctx_params,
                    (void *mctx, void *provctx))
ossl_OSSL_CORE_MAKE_FUNC(int, mac_get_params, (ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(int, mac_get_ctx_params,
                    (void *mctx, ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(int, mac_set_ctx_params,
                    (void *mctx, const ossl_OSSL_PARAM params[]))

/* KDFs and PRFs */

# define ossl_OSSL_FUNC_KDF_NEWCTX                        1
# define ossl_OSSL_FUNC_KDF_DUPCTX                        2
# define ossl_OSSL_FUNC_KDF_FREECTX                       3
# define ossl_OSSL_FUNC_KDF_RESET                         4
# define ossl_OSSL_FUNC_KDF_DERIVE                        5
# define ossl_OSSL_FUNC_KDF_GETTABLE_PARAMS               6
# define ossl_OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS           7
# define ossl_OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS           8
# define ossl_OSSL_FUNC_KDF_GET_PARAMS                    9
# define ossl_OSSL_FUNC_KDF_GET_CTX_PARAMS               10
# define ossl_OSSL_FUNC_KDF_SET_CTX_PARAMS               11

ossl_OSSL_CORE_MAKE_FUNC(void *, kdf_newctx, (void *provctx))
ossl_OSSL_CORE_MAKE_FUNC(void *, kdf_dupctx, (void *src))
ossl_OSSL_CORE_MAKE_FUNC(void, kdf_freectx, (void *kctx))
ossl_OSSL_CORE_MAKE_FUNC(void, kdf_reset, (void *kctx))
ossl_OSSL_CORE_MAKE_FUNC(int, kdf_derive, (void *kctx, unsigned char *key,
                                      size_t keylen, const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *, kdf_gettable_params, (void *provctx))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *, kdf_gettable_ctx_params,
                    (void *kctx, void *provctx))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *, kdf_settable_ctx_params,
                    (void *kctx, void *provctx))
ossl_OSSL_CORE_MAKE_FUNC(int, kdf_get_params, (ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(int, kdf_get_ctx_params,
                    (void *kctx, ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(int, kdf_set_ctx_params,
                    (void *kctx, const ossl_OSSL_PARAM params[]))

/* RAND */

# define ossl_OSSL_FUNC_RAND_NEWCTX                        1
# define ossl_OSSL_FUNC_RAND_FREECTX                       2
# define ossl_OSSL_FUNC_RAND_INSTANTIATE                   3
# define ossl_OSSL_FUNC_RAND_UNINSTANTIATE                 4
# define ossl_OSSL_FUNC_RAND_GENERATE                      5
# define ossl_OSSL_FUNC_RAND_RESEED                        6
# define ossl_OSSL_FUNC_RAND_NONCE                         7
# define ossl_OSSL_FUNC_RAND_ENABLE_LOCKING                8
# define ossl_OSSL_FUNC_RAND_LOCK                          9
# define ossl_OSSL_FUNC_RAND_UNLOCK                       10
# define ossl_OSSL_FUNC_RAND_GETTABLE_PARAMS              11
# define ossl_OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS          12
# define ossl_OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS          13
# define ossl_OSSL_FUNC_RAND_GET_PARAMS                   14
# define ossl_OSSL_FUNC_RAND_GET_CTX_PARAMS               15
# define ossl_OSSL_FUNC_RAND_SET_CTX_PARAMS               16
# define ossl_OSSL_FUNC_RAND_VERIFY_ZEROIZATION           17
# define ossl_OSSL_FUNC_RAND_GET_SEED                     18
# define ossl_OSSL_FUNC_RAND_CLEAR_SEED                   19

ossl_OSSL_CORE_MAKE_FUNC(void *,rand_newctx,
                    (void *provctx, void *parent,
                    const ossl_OSSL_DISPATCH *parent_calls))
ossl_OSSL_CORE_MAKE_FUNC(void,rand_freectx, (void *vctx))
ossl_OSSL_CORE_MAKE_FUNC(int,rand_instantiate,
                    (void *vdrbg, unsigned int strength,
                     int prediction_resistance,
                     const unsigned char *pstr, size_t pstr_len,
                     const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(int,rand_uninstantiate, (void *vdrbg))
ossl_OSSL_CORE_MAKE_FUNC(int,rand_generate,
                    (void *vctx, unsigned char *out, size_t outlen,
                     unsigned int strength, int prediction_resistance,
                     const unsigned char *addin, size_t addin_len))
ossl_OSSL_CORE_MAKE_FUNC(int,rand_reseed,
                    (void *vctx, int prediction_resistance,
                     const unsigned char *ent, size_t ent_len,
                     const unsigned char *addin, size_t addin_len))
ossl_OSSL_CORE_MAKE_FUNC(size_t,rand_nonce,
                    (void *vctx, unsigned char *out, unsigned int strength,
                     size_t min_noncelen, size_t max_noncelen))
ossl_OSSL_CORE_MAKE_FUNC(int,rand_enable_locking, (void *vctx))
ossl_OSSL_CORE_MAKE_FUNC(int,rand_lock, (void *vctx))
ossl_OSSL_CORE_MAKE_FUNC(void,rand_unlock, (void *vctx))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *,rand_gettable_params, (void *provctx))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *,rand_gettable_ctx_params,
                    (void *vctx, void *provctx))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *,rand_settable_ctx_params,
                    (void *vctx, void *provctx))
ossl_OSSL_CORE_MAKE_FUNC(int,rand_get_params, (ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(int,rand_get_ctx_params,
                    (void *vctx, ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(int,rand_set_ctx_params,
                    (void *vctx, const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(void,rand_set_callbacks,
                    (void *vctx, ossl_OSSL_INOUT_CALLBACK *get_entropy,
                     ossl_OSSL_CALLBACK *cleanup_entropy,
                     ossl_OSSL_INOUT_CALLBACK *get_nonce,
                     ossl_OSSL_CALLBACK *cleanup_nonce, void *arg))
ossl_OSSL_CORE_MAKE_FUNC(int,rand_verify_zeroization,
                    (void *vctx))
ossl_OSSL_CORE_MAKE_FUNC(size_t,rand_get_seed,
                    (void *vctx, unsigned char **buffer,
                     int entropy, size_t min_len, size_t max_len,
                     int prediction_resistance,
                     const unsigned char *adin, size_t adin_len))
ossl_OSSL_CORE_MAKE_FUNC(void,rand_clear_seed,
                    (void *vctx, unsigned char *buffer, size_t b_len))

/*-
 * Key management
 *
 * The Key Management takes care of provider side key objects, and includes
 * all current functionality to create them, destroy them, set parameters
 * and key material, etc, essentially everything that manipulates the keys
 * themselves and their parameters.
 *
 * The key objects are commonly refered to as |keydata|, and it MUST be able
 * to contain parameters if the key has any, the public key and the private
 * key.  All parts are optional, but their presence determines what can be
 * done with the key object in terms of encryption, signature, and so on.
 * The assumption from libcrypto is that the key object contains any of the
 * following data combinations:
 *
 * - parameters only
 * - public key only
 * - public key + private key
 * - parameters + public key
 * - parameters + public key + private key
 *
 * What "parameters", "public key" and "private key" means in detail is left
 * to the implementation.  In the case of ossl_DH and ossl_DSA, they would typically
 * include domain parameters, while for certain variants of ossl_RSA, they would
 * typically include PSS or OAEP parameters.
 *
 * Key objects are created with ossl_OSSL_FUNC_keymgmt_new() and destroyed with
 * ossl_OSSL_FUNC_keymgmt_free().  Key objects can have data filled in with
 * ossl_OSSL_FUNC_keymgmt_import().
 *
 * Three functions are made available to check what selection of data is
 * present in a key object: OSSL_FUNC_keymgmt_has_parameters(),
 * OSSL_FUNC_keymgmt_has_public_key(), and OSSL_FUNC_keymgmt_has_private_key(),
 */

/* Key data subset selection - individual bits */
# define ossl_OSSL_KEYMGMT_SELECT_PRIVATE_KEY            0x01
# define ossl_OSSL_KEYMGMT_SELECT_PUBLIC_KEY             0x02
# define ossl_OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS      0x04
# define ossl_OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS       0x80

/* Key data subset selection - combinations */
# define ossl_OSSL_KEYMGMT_SELECT_ALL_PARAMETERS     \
    ( ossl_OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS     \
      | ossl_OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS)
# define ossl_OSSL_KEYMGMT_SELECT_KEYPAIR            \
    ( ossl_OSSL_KEYMGMT_SELECT_PRIVATE_KEY | ossl_OSSL_KEYMGMT_SELECT_PUBLIC_KEY )
# define ossl_OSSL_KEYMGMT_SELECT_ALL                \
    ( ossl_OSSL_KEYMGMT_SELECT_KEYPAIR | ossl_OSSL_KEYMGMT_SELECT_ALL_PARAMETERS )

# define ossl_OSSL_KEYMGMT_VALIDATE_FULL_CHECK              0
# define ossl_OSSL_KEYMGMT_VALIDATE_QUICK_CHECK             1

/* Basic key object creation */
# define ossl_OSSL_FUNC_KEYMGMT_NEW                         1
ossl_OSSL_CORE_MAKE_FUNC(void *, keymgmt_new, (void *provctx))

/* Generation, a more complex constructor */
# define ossl_OSSL_FUNC_KEYMGMT_GEN_INIT                    2
# define ossl_OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE            3
# define ossl_OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS              4
# define ossl_OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS         5
# define ossl_OSSL_FUNC_KEYMGMT_GEN                         6
# define ossl_OSSL_FUNC_KEYMGMT_GEN_CLEANUP                 7
ossl_OSSL_CORE_MAKE_FUNC(void *, keymgmt_gen_init,
                    (void *provctx, int selection, const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(int, keymgmt_gen_set_template,
                    (void *genctx, void *templ))
ossl_OSSL_CORE_MAKE_FUNC(int, keymgmt_gen_set_params,
                    (void *genctx, const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *,
                    keymgmt_gen_settable_params,
                    (void *genctx, void *provctx))
ossl_OSSL_CORE_MAKE_FUNC(void *, keymgmt_gen,
                    (void *genctx, ossl_OSSL_CALLBACK *cb, void *cbarg))
ossl_OSSL_CORE_MAKE_FUNC(void, keymgmt_gen_cleanup, (void *genctx))

/* Key loading by object reference */
# define ossl_OSSL_FUNC_KEYMGMT_LOAD                        8
ossl_OSSL_CORE_MAKE_FUNC(void *, keymgmt_load,
                    (const void *reference, size_t reference_sz))

/* Basic key object destruction */
# define ossl_OSSL_FUNC_KEYMGMT_FREE                       10
ossl_OSSL_CORE_MAKE_FUNC(void, keymgmt_free, (void *keydata))

/* Key object information, with discovery */
#define ossl_OSSL_FUNC_KEYMGMT_GET_PARAMS                  11
#define ossl_OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS             12
ossl_OSSL_CORE_MAKE_FUNC(int, keymgmt_get_params,
                    (void *keydata, ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *, keymgmt_gettable_params,
                    (void *provctx))

#define ossl_OSSL_FUNC_KEYMGMT_SET_PARAMS                  13
#define ossl_OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS             14
ossl_OSSL_CORE_MAKE_FUNC(int, keymgmt_set_params,
                    (void *keydata, const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *, keymgmt_settable_params,
                    (void *provctx))

/* Key checks - discovery of supported operations */
# define ossl_OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME       20
ossl_OSSL_CORE_MAKE_FUNC(const char *, keymgmt_query_operation_name,
                    (int operation_id))

/* Key checks - key data content checks */
# define ossl_OSSL_FUNC_KEYMGMT_HAS                        21
ossl_OSSL_CORE_MAKE_FUNC(int, keymgmt_has, (const void *keydata, int selection))

/* Key checks - validation */
# define ossl_OSSL_FUNC_KEYMGMT_VALIDATE                   22
ossl_OSSL_CORE_MAKE_FUNC(int, keymgmt_validate, (const void *keydata, int selection,
                                            int checktype))

/* Key checks - matching */
# define ossl_OSSL_FUNC_KEYMGMT_MATCH                      23
ossl_OSSL_CORE_MAKE_FUNC(int, keymgmt_match,
                    (const void *keydata1, const void *keydata2,
                     int selection))

/* Import and export functions, with discovery */
# define ossl_OSSL_FUNC_KEYMGMT_IMPORT                     40
# define ossl_OSSL_FUNC_KEYMGMT_IMPORT_TYPES               41
# define ossl_OSSL_FUNC_KEYMGMT_EXPORT                     42
# define ossl_OSSL_FUNC_KEYMGMT_EXPORT_TYPES               43
ossl_OSSL_CORE_MAKE_FUNC(int, keymgmt_import,
                    (void *keydata, int selection, const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *, keymgmt_import_types,
                    (int selection))
ossl_OSSL_CORE_MAKE_FUNC(int, keymgmt_export,
                    (void *keydata, int selection,
                     ossl_OSSL_CALLBACK *param_cb, void *cbarg))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *, keymgmt_export_types,
                    (int selection))

/* Dup function, constructor */
# define ossl_OSSL_FUNC_KEYMGMT_DUP                        44
ossl_OSSL_CORE_MAKE_FUNC(void *, keymgmt_dup,
                    (const void *keydata_from, int selection))

/* Key Exchange */

# define ossl_OSSL_FUNC_KEYEXCH_NEWCTX                      1
# define ossl_OSSL_FUNC_KEYEXCH_INIT                        2
# define ossl_OSSL_FUNC_KEYEXCH_DERIVE                      3
# define ossl_OSSL_FUNC_KEYEXCH_SET_PEER                    4
# define ossl_OSSL_FUNC_KEYEXCH_FREECTX                     5
# define ossl_OSSL_FUNC_KEYEXCH_DUPCTX                      6
# define ossl_OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS              7
# define ossl_OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS         8
# define ossl_OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS              9
# define ossl_OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS        10

ossl_OSSL_CORE_MAKE_FUNC(void *, keyexch_newctx, (void *provctx))
ossl_OSSL_CORE_MAKE_FUNC(int, keyexch_init, (void *ctx, void *provkey,
                                        const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(int, keyexch_derive, (void *ctx,  unsigned char *secret,
                                             size_t *secretlen, size_t outlen))
ossl_OSSL_CORE_MAKE_FUNC(int, keyexch_set_peer, (void *ctx, void *provkey))
ossl_OSSL_CORE_MAKE_FUNC(void, keyexch_freectx, (void *ctx))
ossl_OSSL_CORE_MAKE_FUNC(void *, keyexch_dupctx, (void *ctx))
ossl_OSSL_CORE_MAKE_FUNC(int, keyexch_set_ctx_params, (void *ctx,
                                                     const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *, keyexch_settable_ctx_params,
                    (void *ctx, void *provctx))
ossl_OSSL_CORE_MAKE_FUNC(int, keyexch_get_ctx_params, (void *ctx,
                                                     ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *, keyexch_gettable_ctx_params,
                    (void *ctx, void *provctx))

/* Signature */

# define ossl_OSSL_FUNC_SIGNATURE_NEWCTX                  1
# define ossl_OSSL_FUNC_SIGNATURE_SIGN_INIT               2
# define ossl_OSSL_FUNC_SIGNATURE_SIGN                    3
# define ossl_OSSL_FUNC_SIGNATURE_VERIFY_INIT             4
# define ossl_OSSL_FUNC_SIGNATURE_VERIFY                  5
# define ossl_OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT     6
# define ossl_OSSL_FUNC_SIGNATURE_VERIFY_RECOVER          7
# define ossl_OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT        8
# define ossl_OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE      9
# define ossl_OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL      10
# define ossl_OSSL_FUNC_SIGNATURE_DIGEST_SIGN            11
# define ossl_OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT     12
# define ossl_OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE   13
# define ossl_OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL    14
# define ossl_OSSL_FUNC_SIGNATURE_DIGEST_VERIFY          15
# define ossl_OSSL_FUNC_SIGNATURE_FREECTX                16
# define ossl_OSSL_FUNC_SIGNATURE_DUPCTX                 17
# define ossl_OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS         18
# define ossl_OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS    19
# define ossl_OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS         20
# define ossl_OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS    21
# define ossl_OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS      22
# define ossl_OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS 23
# define ossl_OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS      24
# define ossl_OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS 25

ossl_OSSL_CORE_MAKE_FUNC(void *, signature_newctx, (void *provctx,
                                                  const char *propq))
ossl_OSSL_CORE_MAKE_FUNC(int, signature_sign_init, (void *ctx, void *provkey,
                                               const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(int, signature_sign, (void *ctx,  unsigned char *sig,
                                             size_t *siglen, size_t sigsize,
                                             const unsigned char *tbs,
                                             size_t tbslen))
ossl_OSSL_CORE_MAKE_FUNC(int, signature_verify_init, (void *ctx, void *provkey,
                                                 const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(int, signature_verify, (void *ctx,
                                               const unsigned char *sig,
                                               size_t siglen,
                                               const unsigned char *tbs,
                                               size_t tbslen))
ossl_OSSL_CORE_MAKE_FUNC(int, signature_verify_recover_init,
                    (void *ctx, void *provkey, const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(int, signature_verify_recover,
                    (void *ctx, unsigned char *rout, size_t *routlen,
                     size_t routsize, const unsigned char *sig, size_t siglen))
ossl_OSSL_CORE_MAKE_FUNC(int, signature_digest_sign_init,
                    (void *ctx, const char *mdname, void *provkey,
                     const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(int, signature_digest_sign_update,
                    (void *ctx, const unsigned char *data, size_t datalen))
ossl_OSSL_CORE_MAKE_FUNC(int, signature_digest_sign_final,
                    (void *ctx, unsigned char *sig, size_t *siglen,
                     size_t sigsize))
ossl_OSSL_CORE_MAKE_FUNC(int, signature_digest_sign,
                    (void *ctx, unsigned char *sigret, size_t *siglen,
                     size_t sigsize, const unsigned char *tbs, size_t tbslen))
ossl_OSSL_CORE_MAKE_FUNC(int, signature_digest_verify_init,
                    (void *ctx, const char *mdname, void *provkey,
                     const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(int, signature_digest_verify_update,
                    (void *ctx, const unsigned char *data, size_t datalen))
ossl_OSSL_CORE_MAKE_FUNC(int, signature_digest_verify_final,
                    (void *ctx, const unsigned char *sig, size_t siglen))
ossl_OSSL_CORE_MAKE_FUNC(int, signature_digest_verify,
                    (void *ctx, const unsigned char *sig, size_t siglen,
                     const unsigned char *tbs, size_t tbslen))
ossl_OSSL_CORE_MAKE_FUNC(void, signature_freectx, (void *ctx))
ossl_OSSL_CORE_MAKE_FUNC(void *, signature_dupctx, (void *ctx))
ossl_OSSL_CORE_MAKE_FUNC(int, signature_get_ctx_params,
                    (void *ctx, ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *, signature_gettable_ctx_params,
                    (void *ctx, void *provctx))
ossl_OSSL_CORE_MAKE_FUNC(int, signature_set_ctx_params,
                    (void *ctx, const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *, signature_settable_ctx_params,
                    (void *ctx, void *provctx))
ossl_OSSL_CORE_MAKE_FUNC(int, signature_get_ctx_md_params,
                    (void *ctx, ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *, signature_gettable_ctx_md_params,
                    (void *ctx))
ossl_OSSL_CORE_MAKE_FUNC(int, signature_set_ctx_md_params,
                    (void *ctx, const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *, signature_settable_ctx_md_params,
                    (void *ctx))


/* Asymmetric Ciphers */

# define ossl_OSSL_FUNC_ASYM_CIPHER_NEWCTX                  1
# define ossl_OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT            2
# define ossl_OSSL_FUNC_ASYM_CIPHER_ENCRYPT                 3
# define ossl_OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT            4
# define ossl_OSSL_FUNC_ASYM_CIPHER_DECRYPT                 5
# define ossl_OSSL_FUNC_ASYM_CIPHER_FREECTX                 6
# define ossl_OSSL_FUNC_ASYM_CIPHER_DUPCTX                  7
# define ossl_OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS          8
# define ossl_OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS     9
# define ossl_OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS         10
# define ossl_OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS    11

ossl_OSSL_CORE_MAKE_FUNC(void *, asym_cipher_newctx, (void *provctx))
ossl_OSSL_CORE_MAKE_FUNC(int, asym_cipher_encrypt_init, (void *ctx, void *provkey,
                                                    const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(int, asym_cipher_encrypt, (void *ctx, unsigned char *out,
                                                  size_t *outlen,
                                                  size_t outsize,
                                                  const unsigned char *in,
                                                  size_t inlen))
ossl_OSSL_CORE_MAKE_FUNC(int, asym_cipher_decrypt_init, (void *ctx, void *provkey,
                                                    const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(int, asym_cipher_decrypt, (void *ctx, unsigned char *out,
                                                  size_t *outlen,
                                                  size_t outsize,
                                                  const unsigned char *in,
                                                  size_t inlen))
ossl_OSSL_CORE_MAKE_FUNC(void, asym_cipher_freectx, (void *ctx))
ossl_OSSL_CORE_MAKE_FUNC(void *, asym_cipher_dupctx, (void *ctx))
ossl_OSSL_CORE_MAKE_FUNC(int, asym_cipher_get_ctx_params,
                    (void *ctx, ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *, asym_cipher_gettable_ctx_params,
                    (void *ctx, void *provctx))
ossl_OSSL_CORE_MAKE_FUNC(int, asym_cipher_set_ctx_params,
                    (void *ctx, const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *, asym_cipher_settable_ctx_params,
                    (void *ctx, void *provctx))

/* Asymmetric Key encapsulation */
# define ossl_OSSL_FUNC_KEM_NEWCTX                  1
# define ossl_OSSL_FUNC_KEM_ENCAPSULATE_INIT        2
# define ossl_OSSL_FUNC_KEM_ENCAPSULATE             3
# define ossl_OSSL_FUNC_KEM_DECAPSULATE_INIT        4
# define ossl_OSSL_FUNC_KEM_DECAPSULATE             5
# define ossl_OSSL_FUNC_KEM_FREECTX                 6
# define ossl_OSSL_FUNC_KEM_DUPCTX                  7
# define ossl_OSSL_FUNC_KEM_GET_CTX_PARAMS          8
# define ossl_OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS     9
# define ossl_OSSL_FUNC_KEM_SET_CTX_PARAMS         10
# define ossl_OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS    11

ossl_OSSL_CORE_MAKE_FUNC(void *, kem_newctx, (void *provctx))
ossl_OSSL_CORE_MAKE_FUNC(int, kem_encapsulate_init, (void *ctx, void *provkey,
                                                const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(int, kem_encapsulate, (void *ctx,
                                           unsigned char *out, size_t *outlen,
                                           unsigned char *secret,
                                           size_t *secretlen))
ossl_OSSL_CORE_MAKE_FUNC(int, kem_decapsulate_init, (void *ctx, void *provkey,
                                                const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(int, kem_decapsulate, (void *ctx,
                                           unsigned char *out, size_t *outlen,
                                           const unsigned char *in, size_t inlen))
ossl_OSSL_CORE_MAKE_FUNC(void, kem_freectx, (void *ctx))
ossl_OSSL_CORE_MAKE_FUNC(void *, kem_dupctx, (void *ctx))
ossl_OSSL_CORE_MAKE_FUNC(int, kem_get_ctx_params, (void *ctx, ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *, kem_gettable_ctx_params,
                    (void *ctx, void *provctx))
ossl_OSSL_CORE_MAKE_FUNC(int, kem_set_ctx_params,
                    (void *ctx, const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *, kem_settable_ctx_params,
                    (void *ctx, void *provctx))

/* Encoders and decoders */
# define ossl_OSSL_FUNC_ENCODER_NEWCTX                      1
# define ossl_OSSL_FUNC_ENCODER_FREECTX                     2
# define ossl_OSSL_FUNC_ENCODER_GET_PARAMS                  3
# define ossl_OSSL_FUNC_ENCODER_GETTABLE_PARAMS             4
# define ossl_OSSL_FUNC_ENCODER_SET_CTX_PARAMS              5
# define ossl_OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS         6
# define ossl_OSSL_FUNC_ENCODER_DOES_SELECTION             10
# define ossl_OSSL_FUNC_ENCODER_ENCODE                     11
# define ossl_OSSL_FUNC_ENCODER_IMPORT_OBJECT              20
# define ossl_OSSL_FUNC_ENCODER_FREE_OBJECT                21
ossl_OSSL_CORE_MAKE_FUNC(void *, encoder_newctx, (void *provctx))
ossl_OSSL_CORE_MAKE_FUNC(void, encoder_freectx, (void *ctx))
ossl_OSSL_CORE_MAKE_FUNC(int, encoder_get_params, (ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *, encoder_gettable_params,
                    (void *provctx))
ossl_OSSL_CORE_MAKE_FUNC(int, encoder_set_ctx_params,
                    (void *ctx, const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *, encoder_settable_ctx_params,
                    (void *provctx))

ossl_OSSL_CORE_MAKE_FUNC(int, encoder_does_selection,
                    (void *provctx, int selection))
ossl_OSSL_CORE_MAKE_FUNC(int, encoder_encode,
                    (void *ctx, ossl_OSSL_CORE_BIO *out,
                     const void *obj_raw, const ossl_OSSL_PARAM obj_abstract[],
                     int selection,
                     ossl_OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg))

ossl_OSSL_CORE_MAKE_FUNC(void *, encoder_import_object,
                    (void *ctx, int selection, const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(void, encoder_free_object, (void *obj))

# define ossl_OSSL_FUNC_DECODER_NEWCTX                      1
# define ossl_OSSL_FUNC_DECODER_FREECTX                     2
# define ossl_OSSL_FUNC_DECODER_GET_PARAMS                  3
# define ossl_OSSL_FUNC_DECODER_GETTABLE_PARAMS             4
# define ossl_OSSL_FUNC_DECODER_SET_CTX_PARAMS              5
# define ossl_OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS         6
# define ossl_OSSL_FUNC_DECODER_DOES_SELECTION             10
# define ossl_OSSL_FUNC_DECODER_DECODE                     11
# define ossl_OSSL_FUNC_DECODER_EXPORT_OBJECT              20
ossl_OSSL_CORE_MAKE_FUNC(void *, decoder_newctx, (void *provctx))
ossl_OSSL_CORE_MAKE_FUNC(void, decoder_freectx, (void *ctx))
ossl_OSSL_CORE_MAKE_FUNC(int, decoder_get_params, (ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *, decoder_gettable_params,
                    (void *provctx))
ossl_OSSL_CORE_MAKE_FUNC(int, decoder_set_ctx_params,
                    (void *ctx, const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *, decoder_settable_ctx_params,
                    (void *provctx))

ossl_OSSL_CORE_MAKE_FUNC(int, decoder_does_selection,
                    (void *provctx, int selection))
ossl_OSSL_CORE_MAKE_FUNC(int, decoder_decode,
                    (void *ctx, ossl_OSSL_CORE_BIO *in, int selection,
                     ossl_OSSL_CALLBACK *data_cb, void *data_cbarg,
                     ossl_OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg))
ossl_OSSL_CORE_MAKE_FUNC(int, decoder_export_object,
                    (void *ctx, const void *objref, size_t objref_sz,
                     ossl_OSSL_CALLBACK *export_cb, void *export_cbarg))

/*-
 * Store
 *
 * Objects are scanned by using the 'open', 'load', 'eof' and 'close'
 * functions, which implement an OSSL_STORE loader.
 *
 * store_load() works in a way that's very similar to the decoders, in
 * that they pass an abstract object through a callback, either as a DER
 * octet string or as an object reference, which libcrypto will have to
 * deal with.
 */

#define ossl_OSSL_FUNC_STORE_OPEN                        1
#define ossl_OSSL_FUNC_STORE_ATTACH                      2
#define ossl_OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS         3
#define ossl_OSSL_FUNC_STORE_SET_CTX_PARAMS              4
#define ossl_OSSL_FUNC_STORE_LOAD                        5
#define ossl_OSSL_FUNC_STORE_EOF                         6
#define ossl_OSSL_FUNC_STORE_CLOSE                       7
#define ossl_OSSL_FUNC_STORE_EXPORT_OBJECT               8
ossl_OSSL_CORE_MAKE_FUNC(void *, store_open, (void *provctx, const char *uri))
ossl_OSSL_CORE_MAKE_FUNC(void *, store_attach, (void *provctx, ossl_OSSL_CORE_BIO *in))
ossl_OSSL_CORE_MAKE_FUNC(const ossl_OSSL_PARAM *, store_settable_ctx_params,
                    (void *provctx))
ossl_OSSL_CORE_MAKE_FUNC(int, store_set_ctx_params,
                    (void *loaderctx, const ossl_OSSL_PARAM params[]))
ossl_OSSL_CORE_MAKE_FUNC(int, store_load,
                    (void *loaderctx,
                     ossl_OSSL_CALLBACK *object_cb, void *object_cbarg,
                     ossl_OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg))
ossl_OSSL_CORE_MAKE_FUNC(int, store_eof, (void *loaderctx))
ossl_OSSL_CORE_MAKE_FUNC(int, store_close, (void *loaderctx))
ossl_OSSL_CORE_MAKE_FUNC(int, store_export_object,
                    (void *loaderctx, const void *objref, size_t objref_sz,
                     ossl_OSSL_CALLBACK *export_cb, void *export_cbarg))

# ifdef __cplusplus
}
# endif

#endif
