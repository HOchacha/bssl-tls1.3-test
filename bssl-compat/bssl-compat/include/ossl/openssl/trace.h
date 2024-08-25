/*
 * Copyright 2019-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_TRACE_H
# define ossl_OPENSSL_TRACE_H
# pragma once

# include <stdarg.h>

# include "ossl/openssl/bio.h"

# ifdef  __cplusplus
extern "C" {
# endif

/*
 * TRACE CATEGORIES
 */

/*
 * The trace messages of the OpenSSL libraries are organized into different
 * categories. For every trace category, the application can register a separate
 * tracer callback. When a callback is registered, a so called trace channel is
 * created for this category. This channel consists essentially of an internal
 * ossl_BIO which sends all trace output it receives to the registered application
 * callback.
 *
 * The ALL category can be used as a fallback category to register a single
 * channel which receives the output from all categories. However, if the
 * application intends to print the trace channel name in the line prefix,
 * it is better to register channels for all categories separately.
 * (This is how the openssl application does it.)
 */
# define ossl_OSSL_TRACE_CATEGORY_ALL                 0 /* The fallback */
# define ossl_OSSL_TRACE_CATEGORY_TRACE               1
# define ossl_OSSL_TRACE_CATEGORY_INIT                2
# define ossl_OSSL_TRACE_CATEGORY_TLS                 3
# define ossl_OSSL_TRACE_CATEGORY_TLS_CIPHER          4
# define ossl_OSSL_TRACE_CATEGORY_CONF                5
# define ossl_OSSL_TRACE_CATEGORY_ENGINE_TABLE        6
# define ossl_OSSL_TRACE_CATEGORY_ENGINE_REF_COUNT    7
# define ossl_OSSL_TRACE_CATEGORY_PKCS5V2             8
# define ossl_OSSL_TRACE_CATEGORY_PKCS12_KEYGEN       9
# define ossl_OSSL_TRACE_CATEGORY_PKCS12_DECRYPT     10
# define ossl_OSSL_TRACE_CATEGORY_X509V3_POLICY      11
# define ossl_OSSL_TRACE_CATEGORY_BN_CTX             12
# define ossl_OSSL_TRACE_CATEGORY_CMP                13
# define ossl_OSSL_TRACE_CATEGORY_STORE              14
# define ossl_OSSL_TRACE_CATEGORY_DECODER            15
# define ossl_OSSL_TRACE_CATEGORY_ENCODER            16
# define ossl_OSSL_TRACE_CATEGORY_REF_COUNT          17
/* Count of available categories. */
# define ossl_OSSL_TRACE_CATEGORY_NUM                18

/* Returns the trace category number for the given |name| */
int ossl_OSSL_trace_get_category_num(const char *name);

/* Returns the trace category name for the given |num| */
const char *ossl_OSSL_trace_get_category_name(int num);

/*
 * TRACE CONSUMERS
 */

/*
 * Enables tracing for the given |category| by providing a ossl_BIO sink
 * as |channel|. If a null pointer is passed as |channel|, an existing
 * trace channel is removed and tracing for the category is disabled.
 *
 * Returns 1 on success and 0 on failure
 */
int ossl_OSSL_trace_set_channel(int category, ossl_BIO* channel);

/*
 * Attach a prefix and a suffix to the given |category|, to be printed at the
 * beginning and at the end of each trace output group, i.e. when
 * ossl_OSSL_trace_begin() and ossl_OSSL_trace_end() are called.
 * If a null pointer is passed as argument, the existing prefix or suffix is
 * removed.
 *
 * They return 1 on success and 0 on failure
 */
int ossl_OSSL_trace_set_prefix(int category, const char *prefix);
int ossl_OSSL_trace_set_suffix(int category, const char *suffix);

/*
 * ossl_OSSL_trace_cb is the type tracing callback provided by the application.
 * It MUST return the number of bytes written, or 0 on error (in other words,
 * it can never write zero bytes).
 *
 * The |buffer| will always contain text, which may consist of several lines.
 * The |data| argument points to whatever data was provided by the application
 * when registering the tracer function.
 *
 * The |category| number is given, as well as a |cmd| number, described below.
 */
typedef size_t (*ossl_OSSL_trace_cb)(const char *buffer, size_t count,
                                int category, int cmd, void *data);
/*
 * Possible |cmd| numbers.
 */
# define ossl_OSSL_TRACE_CTRL_BEGIN  0
# define ossl_OSSL_TRACE_CTRL_WRITE  1
# define ossl_OSSL_TRACE_CTRL_END    2

/*
 * Enables tracing for the given |category| by creating an internal
 * trace channel which sends the output to the given |callback|.
 * If a null pointer is passed as callback, an existing trace channel
 * is removed and tracing for the category is disabled.
 *
 * NOTE: ossl_OSSL_trace_set_channel() and ossl_OSSL_trace_set_callback() are mutually
 *       exclusive.
 *
 * Returns 1 on success and 0 on failure
 */
int ossl_OSSL_trace_set_callback(int category, ossl_OSSL_trace_cb callback, void *data);

/*
 * TRACE PRODUCERS
 */

/*
 * Returns 1 if tracing for the specified category is enabled, otherwise 0
 */
int ossl_OSSL_trace_enabled(int category);

/*
 * Wrap a group of tracing output calls.  ossl_OSSL_trace_begin() locks tracing and
 * returns the trace channel associated with the given category, or NULL if no
 * channel is associated with the category.  ossl_OSSL_trace_end() unlocks tracing.
 *
 * Usage:
 *
 *    ossl_BIO *out;
 *    if ((out = ossl_OSSL_trace_begin(category)) != NULL) {
 *        ...
 *        BIO_fprintf(out, ...);
 *        ...
 *        ossl_OSSL_trace_end(category, out);
 *    }
 *
 * See also the convenience macros ossl_OSSL_TRACE_BEGIN and ossl_OSSL_TRACE_END below.
 */
ossl_BIO *ossl_OSSL_trace_begin(int category);
void ossl_OSSL_trace_end(int category, ossl_BIO *channel);

/*
 * ossl_OSSL_TRACE* Convenience Macros
 */

/*
 * When the tracing feature is disabled, these macros are defined to
 * produce dead code, which a good compiler should eliminate.
 */

/*
 * ossl_OSSL_TRACE_BEGIN, ossl_OSSL_TRACE_END - Define a Trace Group
 *
 * These two macros can be used to create a block which is executed only
 * if the corresponding trace category is enabled. Inside this block, a
 * local variable named |trc_out| is defined, which points to the channel
 * associated with the given trace category.
 *
 * Usage: (using 'TLS' as an example category)
 *
 *     ossl_OSSL_TRACE_BEGIN(TLS) {
 *
 *         BIO_fprintf(trc_out, ... );
 *
 *     } ossl_OSSL_TRACE_END(TLS);
 *
 *
 * This expands to the following code
 *
 *     do {
 *         ossl_BIO *trc_out = ossl_OSSL_trace_begin(ossl_OSSL_TRACE_CATEGORY_TLS);
 *         if (trc_out != NULL) {
 *             ...
 *             BIO_fprintf(trc_out, ...);
 *         }
 *         ossl_OSSL_trace_end(ossl_OSSL_TRACE_CATEGORY_TLS, trc_out);
 *     } while (0);
 *
 * The use of the inner '{...}' group and the trailing ';' is enforced
 * by the definition of the macros in order to make the code look as much
 * like C code as possible.
 *
 * Before returning from inside the trace block, it is necessary to
 * call ossl_OSSL_TRACE_CANCEL(category).
 */

# if !defined ossl_OPENSSL_NO_TRACE && !defined FIPS_MODULE

#  define ossl_OSSL_TRACE_BEGIN(category) \
    do { \
        ossl_BIO *trc_out = ossl_OSSL_trace_begin(OSSL_TRACE_CATEGORY_##category); \
 \
        if (trc_out != NULL)

#  define ossl_OSSL_TRACE_END(category) \
        ossl_OSSL_trace_end(OSSL_TRACE_CATEGORY_##category, trc_out); \
    } while (0)

#  define ossl_OSSL_TRACE_CANCEL(category) \
        ossl_OSSL_trace_end(OSSL_TRACE_CATEGORY_##category, trc_out) \

# else

#  define ossl_OSSL_TRACE_BEGIN(category)           \
    do {                                        \
        ossl_BIO *trc_out = NULL;                    \
        if (0)

#  define ossl_OSSL_TRACE_END(category)             \
    } while(0)

#  define ossl_OSSL_TRACE_CANCEL(category)          \
    ((void)0)

# endif

/*
 * ossl_OSSL_TRACE_ENABLED() - Check whether tracing is enabled for |category|
 *
 * Usage:
 *
 *     if (ossl_OSSL_TRACE_ENABLED(TLS)) {
 *         ...
 *     }
 */
# if !defined ossl_OPENSSL_NO_TRACE && !defined FIPS_MODULE

#  define ossl_OSSL_TRACE_ENABLED(category) \
    ossl_OSSL_trace_enabled(OSSL_TRACE_CATEGORY_##category)

# else

#  define ossl_OSSL_TRACE_ENABLED(category) (0)

# endif

/*
 * ossl_OSSL_TRACE*() - OneShot Trace Macros
 *
 * These macros are intended to produce a simple printf-style trace output.
 * Unfortunately, C90 macros don't support variable arguments, so the
 * "vararg" ossl_OSSL_TRACEV() macro has a rather weird usage pattern:
 *
 *    ossl_OSSL_TRACEV(category, (trc_out, "format string", ...args...));
 *
 * Where 'channel' is the literal symbol of this name, not a variable.
 * For that reason, it is currently not intended to be used directly,
 * but only as helper macro for the other oneshot trace macros
 * ossl_OSSL_TRACE(), ossl_OSSL_TRACE1(), ossl_OSSL_TRACE2(), ...
 *
 * Usage:
 *
 *    ossl_OSSL_TRACE(INIT, "Hello world!\n");
 *    ossl_OSSL_TRACE1(TLS, "The answer is %d\n", 42);
 *    ossl_OSSL_TRACE2(TLS, "The ultimate question to answer %d is '%s'\n",
 *                42, "What do you get when you multiply six by nine?");
 */

# if !defined ossl_OPENSSL_NO_TRACE && !defined FIPS_MODULE

#  define ossl_OSSL_TRACEV(category, args) \
    ossl_OSSL_TRACE_BEGIN(category) \
        ossl_BIO_printf args; \
    ossl_OSSL_TRACE_END(category)

# else

#  define ossl_OSSL_TRACEV(category, args) ((void)0)

# endif

# define ossl_OSSL_TRACE(category, text) \
    ossl_OSSL_TRACEV(category, (trc_out, "%s", text))

# define ossl_OSSL_TRACE1(category, format, arg1) \
    ossl_OSSL_TRACEV(category, (trc_out, format, arg1))
# define ossl_OSSL_TRACE2(category, format, arg1, arg2) \
    ossl_OSSL_TRACEV(category, (trc_out, format, arg1, arg2))
# define ossl_OSSL_TRACE3(category, format, arg1, arg2, arg3) \
    ossl_OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3))
# define ossl_OSSL_TRACE4(category, format, arg1, arg2, arg3, arg4) \
    ossl_OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3, arg4))
# define ossl_OSSL_TRACE5(category, format, arg1, arg2, arg3, arg4, arg5) \
    ossl_OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3, arg4, arg5))
# define ossl_OSSL_TRACE6(category, format, arg1, arg2, arg3, arg4, arg5, arg6) \
    ossl_OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3, arg4, arg5, arg6))
# define ossl_OSSL_TRACE7(category, format, arg1, arg2, arg3, arg4, arg5, arg6, arg7) \
    ossl_OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3, arg4, arg5, arg6, arg7))
# define ossl_OSSL_TRACE8(category, format, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) \
    ossl_OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8))
# define ossl_OSSL_TRACE9(category, format, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9) \
    ossl_OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9))

# ifdef  __cplusplus
}
# endif

#endif
