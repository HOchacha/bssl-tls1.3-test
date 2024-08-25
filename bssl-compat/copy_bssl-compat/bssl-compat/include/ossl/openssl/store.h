/*
 * Copyright 2016-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_STORE_H
# define ossl_OPENSSL_STORE_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_OSSL_STORE_H
# endif

# include <stdarg.h>
# include "ossl/openssl/types.h"
# include "ossl/openssl/pem.h"
# include "ossl/openssl/storeerr.h"

# ifdef  __cplusplus
extern "C" {
# endif

/*-
 *  The main OSSL_STORE functions.
 *  ------------------------------
 *
 *  These allow applications to open a channel to a resource with supported
 *  data (keys, certs, crls, ...), read the data a piece at a time and decide
 *  what to do with it, and finally close.
 */

typedef struct ossl_ossl_store_ctx_st ossl_OSSL_STORE_CTX;

/*
 * Typedef for the ossl_OSSL_STORE_INFO post processing callback.  This can be used
 * to massage the given ossl_OSSL_STORE_INFO, or to drop it entirely (by returning
 * NULL).
 */
typedef ossl_OSSL_STORE_INFO *(*ossl_OSSL_STORE_post_process_info_fn)(ossl_OSSL_STORE_INFO *,
                                                            void *);

/*
 * Open a channel given a URI.  The given ossl_UI method will be used any time the
 * loader needs extra input, for example when a password or pin is needed, and
 * will be passed the same user data every time it's needed in this context.
 *
 * Returns a context reference which represents the channel to communicate
 * through.
 */
ossl_OSSL_STORE_CTX *
ossl_OSSL_STORE_open(const char *uri, const ossl_UI_METHOD *ui_method, void *ui_data,
                ossl_OSSL_STORE_post_process_info_fn post_process,
                void *post_process_data);
ossl_OSSL_STORE_CTX *
ossl_OSSL_STORE_open_ex(const char *uri, ossl_OSSL_LIB_CTX *libctx, const char *propq,
                   const ossl_UI_METHOD *ui_method, void *ui_data,
                   const ossl_OSSL_PARAM params[],
                   ossl_OSSL_STORE_post_process_info_fn post_process,
                   void *post_process_data);

/*
 * Control / fine tune the OSSL_STORE channel.  |cmd| determines what is to be
 * done, and depends on the underlying loader (use OSSL_STORE_get0_scheme to
 * determine which loader is used), except for common commands (see below).
 * Each command takes different arguments.
 */
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_OSSL_STORE_ctrl(ossl_OSSL_STORE_CTX *ctx, int cmd,
                                          ... /* args */);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_OSSL_STORE_vctrl(ossl_OSSL_STORE_CTX *ctx, int cmd,
                                           va_list args);
# endif

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0

/*
 * Common ctrl commands that different loaders may choose to support.
 */
/* int on = 0 or 1; STORE_ctrl(ctx, STORE_C_USE_SECMEM, &on); */
# define ossl_OSSL_STORE_C_USE_SECMEM      1
/* Where custom commands start */
# define ossl_OSSL_STORE_C_CUSTOM_START    100

# endif

/*
 * Read one data item (a key, a cert, a CRL) that is supported by the OSSL_STORE
 * functionality, given a context.
 * Returns a ossl_OSSL_STORE_INFO pointer, from which OpenSSL typed data can be
 * extracted with ossl_OSSL_STORE_INFO_get0_PKEY(), ossl_OSSL_STORE_INFO_get0_CERT(), ...
 * NULL is returned on error, which may include that the data found at the URI
 * can't be figured out for certain or is ambiguous.
 */
ossl_OSSL_STORE_INFO *ossl_OSSL_STORE_load(ossl_OSSL_STORE_CTX *ctx);

/*
 * Check if end of data (end of file) is reached
 * Returns 1 on end, 0 otherwise.
 */
int ossl_OSSL_STORE_eof(ossl_OSSL_STORE_CTX *ctx);

/*
 * Check if an error occurred
 * Returns 1 if it did, 0 otherwise.
 */
int ossl_OSSL_STORE_error(ossl_OSSL_STORE_CTX *ctx);

/*
 * Close the channel
 * Returns 1 on success, 0 on error.
 */
int ossl_OSSL_STORE_close(ossl_OSSL_STORE_CTX *ctx);

/*
 * Attach to a ossl_BIO.  This works like ossl_OSSL_STORE_open() except it takes a
 * ossl_BIO instead of a uri, along with a scheme to use when reading.
 * The given ossl_UI method will be used any time the loader needs extra input,
 * for example when a password or pin is needed, and will be passed the
 * same user data every time it's needed in this context.
 *
 * Returns a context reference which represents the channel to communicate
 * through.
 *
 * Note that this function is considered unsafe, all depending on what the
 * ossl_BIO actually reads.
 */
ossl_OSSL_STORE_CTX *ossl_OSSL_STORE_attach(ossl_BIO *bio, const char *scheme,
                                  ossl_OSSL_LIB_CTX *libctx, const char *propq,
                                  const ossl_UI_METHOD *ui_method, void *ui_data,
                                  const ossl_OSSL_PARAM params[],
                                  ossl_OSSL_STORE_post_process_info_fn post_process,
                                  void *post_process_data);

/*-
 *  Extracting OpenSSL types from and creating new OSSL_STORE_INFOs
 *  ---------------------------------------------------------------
 */

/*
 * Types of data that can be ossl_stored in a ossl_OSSL_STORE_INFO.
 * ossl_OSSL_STORE_INFO_NAME is typically found when getting a listing of
 * available "files" / "tokens" / what have you.
 */
# define ossl_OSSL_STORE_INFO_NAME           1   /* char * */
# define ossl_OSSL_STORE_INFO_PARAMS         2   /* ossl_EVP_PKEY * */
# define ossl_OSSL_STORE_INFO_PUBKEY         3   /* ossl_EVP_PKEY * */
# define ossl_OSSL_STORE_INFO_PKEY           4   /* ossl_EVP_PKEY * */
# define ossl_OSSL_STORE_INFO_CERT           5   /* ossl_X509 * */
# define ossl_OSSL_STORE_INFO_CRL            6   /* ossl_X509_CRL * */

/*
 * Functions to generate OSSL_STORE_INFOs, one function for each type we
 * support having in them, as well as a generic constructor.
 *
 * In all cases, ownership of the object is transferred to the ossl_OSSL_STORE_INFO
 * and will therefore be freed when the ossl_OSSL_STORE_INFO is freed.
 */
ossl_OSSL_STORE_INFO *ossl_OSSL_STORE_INFO_new(int type, void *data);
ossl_OSSL_STORE_INFO *ossl_OSSL_STORE_INFO_new_NAME(char *name);
int ossl_OSSL_STORE_INFO_set0_NAME_description(ossl_OSSL_STORE_INFO *info, char *desc);
ossl_OSSL_STORE_INFO *ossl_OSSL_STORE_INFO_new_PARAMS(ossl_EVP_PKEY *params);
ossl_OSSL_STORE_INFO *ossl_OSSL_STORE_INFO_new_PUBKEY(ossl_EVP_PKEY *pubkey);
ossl_OSSL_STORE_INFO *ossl_OSSL_STORE_INFO_new_PKEY(ossl_EVP_PKEY *pkey);
ossl_OSSL_STORE_INFO *ossl_OSSL_STORE_INFO_new_CERT(ossl_X509 *x509);
ossl_OSSL_STORE_INFO *ossl_OSSL_STORE_INFO_new_CRL(ossl_X509_CRL *crl);

/*
 * Functions to try to extract data from a ossl_OSSL_STORE_INFO.
 */
int ossl_OSSL_STORE_INFO_get_type(const ossl_OSSL_STORE_INFO *info);
void *ossl_OSSL_STORE_INFO_get0_data(int type, const ossl_OSSL_STORE_INFO *info);
const char *ossl_OSSL_STORE_INFO_get0_NAME(const ossl_OSSL_STORE_INFO *info);
char *ossl_OSSL_STORE_INFO_get1_NAME(const ossl_OSSL_STORE_INFO *info);
const char *ossl_OSSL_STORE_INFO_get0_NAME_description(const ossl_OSSL_STORE_INFO *info);
char *ossl_OSSL_STORE_INFO_get1_NAME_description(const ossl_OSSL_STORE_INFO *info);
ossl_EVP_PKEY *ossl_OSSL_STORE_INFO_get0_PARAMS(const ossl_OSSL_STORE_INFO *info);
ossl_EVP_PKEY *ossl_OSSL_STORE_INFO_get1_PARAMS(const ossl_OSSL_STORE_INFO *info);
ossl_EVP_PKEY *ossl_OSSL_STORE_INFO_get0_PUBKEY(const ossl_OSSL_STORE_INFO *info);
ossl_EVP_PKEY *ossl_OSSL_STORE_INFO_get1_PUBKEY(const ossl_OSSL_STORE_INFO *info);
ossl_EVP_PKEY *ossl_OSSL_STORE_INFO_get0_PKEY(const ossl_OSSL_STORE_INFO *info);
ossl_EVP_PKEY *ossl_OSSL_STORE_INFO_get1_PKEY(const ossl_OSSL_STORE_INFO *info);
ossl_X509 *ossl_OSSL_STORE_INFO_get0_CERT(const ossl_OSSL_STORE_INFO *info);
ossl_X509 *ossl_OSSL_STORE_INFO_get1_CERT(const ossl_OSSL_STORE_INFO *info);
ossl_X509_CRL *ossl_OSSL_STORE_INFO_get0_CRL(const ossl_OSSL_STORE_INFO *info);
ossl_X509_CRL *ossl_OSSL_STORE_INFO_get1_CRL(const ossl_OSSL_STORE_INFO *info);

const char *ossl_OSSL_STORE_INFO_type_string(int type);

/*
 * Free the ossl_OSSL_STORE_INFO
 */
void ossl_OSSL_STORE_INFO_free(ossl_OSSL_STORE_INFO *info);


/*-
 *  Functions to construct a search URI from a base URI and search criteria
 *  -----------------------------------------------------------------------
 */

/* OSSL_STORE search types */
# define ossl_OSSL_STORE_SEARCH_BY_NAME              1 /* subject in certs, issuer in CRLs */
# define ossl_OSSL_STORE_SEARCH_BY_ISSUER_SERIAL     2
# define ossl_OSSL_STORE_SEARCH_BY_KEY_FINGERPRINT   3
# define ossl_OSSL_STORE_SEARCH_BY_ALIAS             4

/* To check what search types the scheme handler supports */
int ossl_OSSL_STORE_supports_search(ossl_OSSL_STORE_CTX *ctx, int search_type);

/* Search term constructors */
/*
 * The input is considered to be owned by the caller, and must therefore
 * remain present throughout the lifetime of the returned ossl_OSSL_STORE_SEARCH
 */
ossl_OSSL_STORE_SEARCH *ossl_OSSL_STORE_SEARCH_by_name(ossl_X509_NAME *name);
ossl_OSSL_STORE_SEARCH *ossl_OSSL_STORE_SEARCH_by_issuer_serial(ossl_X509_NAME *name,
                                                      const ossl_ASN1_INTEGER
                                                      *serial);
ossl_OSSL_STORE_SEARCH *ossl_OSSL_STORE_SEARCH_by_key_fingerprint(const ossl_EVP_MD *digest,
                                                        const unsigned char
                                                        *bytes, size_t len);
ossl_OSSL_STORE_SEARCH *ossl_OSSL_STORE_SEARCH_by_alias(const char *alias);

/* Search term destructor */
void ossl_OSSL_STORE_SEARCH_free(ossl_OSSL_STORE_SEARCH *search);

/* Search term accessors */
int ossl_OSSL_STORE_SEARCH_get_type(const ossl_OSSL_STORE_SEARCH *criterion);
ossl_X509_NAME *ossl_OSSL_STORE_SEARCH_get0_name(const ossl_OSSL_STORE_SEARCH *criterion);
const ossl_ASN1_INTEGER *ossl_OSSL_STORE_SEARCH_get0_serial(const ossl_OSSL_STORE_SEARCH
                                                  *criterion);
const unsigned char *ossl_OSSL_STORE_SEARCH_get0_bytes(const ossl_OSSL_STORE_SEARCH
                                                  *criterion, size_t *length);
const char *ossl_OSSL_STORE_SEARCH_get0_string(const ossl_OSSL_STORE_SEARCH *criterion);
const ossl_EVP_MD *ossl_OSSL_STORE_SEARCH_get0_digest(const ossl_OSSL_STORE_SEARCH *criterion);

/*
 * Add search criterion and expected return type (which can be unspecified)
 * to the loading channel.  This MUST happen before the first ossl_OSSL_STORE_load().
 */
int ossl_OSSL_STORE_expect(ossl_OSSL_STORE_CTX *ctx, int expected_type);
int ossl_OSSL_STORE_find(ossl_OSSL_STORE_CTX *ctx, const ossl_OSSL_STORE_SEARCH *search);


/*-
 *  Function to fetch a loader and extract data from it
 *  ---------------------------------------------------
 */

typedef struct ossl_ossl_store_loader_st ossl_OSSL_STORE_LOADER;

ossl_OSSL_STORE_LOADER *ossl_OSSL_STORE_LOADER_fetch(ossl_OSSL_LIB_CTX *libctx,
                                           const char *scheme,
                                           const char *properties);
int ossl_OSSL_STORE_LOADER_up_ref(ossl_OSSL_STORE_LOADER *loader);
void ossl_OSSL_STORE_LOADER_free(ossl_OSSL_STORE_LOADER *loader);
const ossl_OSSL_PROVIDER *ossl_OSSL_STORE_LOADER_get0_provider(const ossl_OSSL_STORE_LOADER *
                                                loader);
const char *ossl_OSSL_STORE_LOADER_get0_properties(const ossl_OSSL_STORE_LOADER *loader);
const char *ossl_OSSL_STORE_LOADER_get0_description(const ossl_OSSL_STORE_LOADER *loader);
int ossl_OSSL_STORE_LOADER_is_a(const ossl_OSSL_STORE_LOADER *loader,
                           const char *scheme);
void ossl_OSSL_STORE_LOADER_do_all_provided(ossl_OSSL_LIB_CTX *libctx,
                                       void (*fn)(ossl_OSSL_STORE_LOADER *loader,
                                                  void *arg),
                                       void *arg);
int ossl_OSSL_STORE_LOADER_names_do_all(const ossl_OSSL_STORE_LOADER *loader,
                                   void (*fn)(const char *name, void *data),
                                   void *data);

/*-
 *  Function to register a loader for the given URI scheme.
 *  -------------------------------------------------------
 *
 *  The loader receives all the main components of an URI except for the
 *  scheme.
 */

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0

/* struct ossl_ossl_store_loader_ctx_st is defined differently by each loader */
typedef struct ossl_ossl_store_loader_ctx_st ossl_OSSL_STORE_LOADER_CTX;
typedef ossl_OSSL_STORE_LOADER_CTX *(*ossl_OSSL_STORE_open_fn)
    (const ossl_OSSL_STORE_LOADER *loader, const char *uri,
     const ossl_UI_METHOD *ui_method, void *ui_data);
typedef ossl_OSSL_STORE_LOADER_CTX *(*ossl_OSSL_STORE_open_ex_fn)
    (const ossl_OSSL_STORE_LOADER *loader,
     const char *uri, ossl_OSSL_LIB_CTX *libctx, const char *propq,
     const ossl_UI_METHOD *ui_method, void *ui_data);

typedef ossl_OSSL_STORE_LOADER_CTX *(*ossl_OSSL_STORE_attach_fn)
    (const ossl_OSSL_STORE_LOADER *loader, ossl_BIO *bio,
     ossl_OSSL_LIB_CTX *libctx, const char *propq,
     const ossl_UI_METHOD *ui_method, void *ui_data);
typedef int (*ossl_OSSL_STORE_ctrl_fn)
    (ossl_OSSL_STORE_LOADER_CTX *ctx, int cmd, va_list args);
typedef int (*ossl_OSSL_STORE_expect_fn)
    (ossl_OSSL_STORE_LOADER_CTX *ctx, int expected);
typedef int (*ossl_OSSL_STORE_find_fn)
    (ossl_OSSL_STORE_LOADER_CTX *ctx, const ossl_OSSL_STORE_SEARCH *criteria);
typedef ossl_OSSL_STORE_INFO *(*ossl_OSSL_STORE_load_fn)
    (ossl_OSSL_STORE_LOADER_CTX *ctx, const ossl_UI_METHOD *ui_method, void *ui_data);
typedef int (*ossl_OSSL_STORE_eof_fn)(ossl_OSSL_STORE_LOADER_CTX *ctx);
typedef int (*ossl_OSSL_STORE_error_fn)(ossl_OSSL_STORE_LOADER_CTX *ctx);
typedef int (*ossl_OSSL_STORE_close_fn)(ossl_OSSL_STORE_LOADER_CTX *ctx);

# endif
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0
ossl_OSSL_STORE_LOADER *ossl_OSSL_STORE_LOADER_new(ossl_ENGINE *e, const char *scheme);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_OSSL_STORE_LOADER_set_open(ossl_OSSL_STORE_LOADER *loader,
                               ossl_OSSL_STORE_open_fn open_function);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_OSSL_STORE_LOADER_set_open_ex(ossl_OSSL_STORE_LOADER *loader,
                                  ossl_OSSL_STORE_open_ex_fn open_ex_function);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_OSSL_STORE_LOADER_set_attach(ossl_OSSL_STORE_LOADER *loader,
                                 ossl_OSSL_STORE_attach_fn attach_function);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_OSSL_STORE_LOADER_set_ctrl(ossl_OSSL_STORE_LOADER *loader,
                               ossl_OSSL_STORE_ctrl_fn ctrl_function);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_OSSL_STORE_LOADER_set_expect(ossl_OSSL_STORE_LOADER *loader,
                                 ossl_OSSL_STORE_expect_fn expect_function);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_OSSL_STORE_LOADER_set_find(ossl_OSSL_STORE_LOADER *loader,
                               ossl_OSSL_STORE_find_fn find_function);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_OSSL_STORE_LOADER_set_load(ossl_OSSL_STORE_LOADER *loader,
                               ossl_OSSL_STORE_load_fn load_function);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_OSSL_STORE_LOADER_set_eof(ossl_OSSL_STORE_LOADER *loader,
                              ossl_OSSL_STORE_eof_fn eof_function);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_OSSL_STORE_LOADER_set_error(ossl_OSSL_STORE_LOADER *loader,
                                ossl_OSSL_STORE_error_fn error_function);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_OSSL_STORE_LOADER_set_close(ossl_OSSL_STORE_LOADER *loader,
                                ossl_OSSL_STORE_close_fn close_function);
ossl_OSSL_DEPRECATEDIN_3_0
const ossl_ENGINE *ossl_OSSL_STORE_LOADER_get0_engine(const ossl_OSSL_STORE_LOADER *loader);
ossl_OSSL_DEPRECATEDIN_3_0
const char * ossl_OSSL_STORE_LOADER_get0_scheme(const ossl_OSSL_STORE_LOADER *loader);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_OSSL_STORE_register_loader(ossl_OSSL_STORE_LOADER *loader);
ossl_OSSL_DEPRECATEDIN_3_0
ossl_OSSL_STORE_LOADER *ossl_OSSL_STORE_unregister_loader(const char *scheme);
# endif

/*-
 *  Functions to list STORE loaders
 *  -------------------------------
 */
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_OSSL_STORE_do_all_loaders(void (*do_function)(const ossl_OSSL_STORE_LOADER *loader,
                                                  void *do_arg),
                              void *do_arg);
# endif

# ifdef  __cplusplus
}
# endif
#endif
