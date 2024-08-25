/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_E_OS2_H
# define ossl_OPENSSL_E_OS2_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_E_OS2_H
# endif

# include "ossl/openssl/opensslconf.h"

#ifdef  __cplusplus
extern "C" {
#endif

/******************************************************************************
 * Detect operating systems.  This probably needs completing.
 * The result is that at least one ossl_OPENSSL_SYS_os macro should be defined.
 * However, if none is defined, Unix is assumed.
 **/

# define ossl_OPENSSL_SYS_UNIX

/* --------------------- Microsoft operating systems ---------------------- */

/*
 * Note that MSDOS actually denotes 32-bit environments running on top of
 * MS-DOS, such as DJGPP one.
 */
# if defined(ossl_OPENSSL_SYS_MSDOS)
#  undef ossl_OPENSSL_SYS_UNIX
# endif

/*
 * For 32 bit environment, there seems to be the CygWin environment and then
 * all the others that try to do the same thing Microsoft does...
 */
/*
 * UEFI lives here because it might be built with a Microsoft toolchain and
 * we need to avoid the false positive match on Windows.
 */
# if defined(ossl_OPENSSL_SYS_UEFI)
#  undef ossl_OPENSSL_SYS_UNIX
# elif defined(ossl_OPENSSL_SYS_UWIN)
#  undef ossl_OPENSSL_SYS_UNIX
#  define ossl_OPENSSL_SYS_WIN32_UWIN
# else
#  if defined(__CYGWIN__) || defined(ossl_OPENSSL_SYS_CYGWIN)
#   define ossl_OPENSSL_SYS_WIN32_CYGWIN
#  else
#   if defined(_WIN32) || defined(ossl_OPENSSL_SYS_WIN32)
#    undef ossl_OPENSSL_SYS_UNIX
#    if !defined(ossl_OPENSSL_SYS_WIN32)
#     define ossl_OPENSSL_SYS_WIN32
#    endif
#   endif
#   if defined(_WIN64) || defined(ossl_OPENSSL_SYS_WIN64)
#    undef ossl_OPENSSL_SYS_UNIX
#    if !defined(ossl_OPENSSL_SYS_WIN64)
#     define ossl_OPENSSL_SYS_WIN64
#    endif
#   endif
#   if defined(ossl_OPENSSL_SYS_WINNT)
#    undef ossl_OPENSSL_SYS_UNIX
#   endif
#   if defined(ossl_OPENSSL_SYS_WINCE)
#    undef ossl_OPENSSL_SYS_UNIX
#   endif
#  endif
# endif

/* Anything that tries to look like Microsoft is "Windows" */
# if defined(ossl_OPENSSL_SYS_WIN32) || defined(ossl_OPENSSL_SYS_WIN64) || defined(ossl_OPENSSL_SYS_WINNT) || defined(ossl_OPENSSL_SYS_WINCE)
#  undef ossl_OPENSSL_SYS_UNIX
#  define ossl_OPENSSL_SYS_WINDOWS
#  ifndef ossl_OPENSSL_SYS_MSDOS
#   define ossl_OPENSSL_SYS_MSDOS
#  endif
# endif

/*
 * DLL settings.  This part is a bit tough, because it's up to the
 * application implementor how he or she will link the application, so it
 * requires some macro to be used.
 */
# ifdef ossl_OPENSSL_SYS_WINDOWS
#  ifndef ossl_OPENSSL_OPT_WINDLL
#   if defined(_WINDLL)         /* This is used when building OpenSSL to
                                 * indicate that DLL linkage should be used */
#    define ossl_OPENSSL_OPT_WINDLL
#   endif
#  endif
# endif

/* ------------------------------- OpenVMS -------------------------------- */
# if defined(__VMS) || defined(VMS)
#  if !defined(ossl_OPENSSL_SYS_VMS)
#   undef ossl_OPENSSL_SYS_UNIX
#   define ossl_OPENSSL_SYS_VMS
#  endif
#  if defined(__DECC)
#   define ossl_OPENSSL_SYS_VMS_DECC
#  elif defined(__DECCXX)
#   define ossl_OPENSSL_SYS_VMS_DECC
#   define ossl_OPENSSL_SYS_VMS_DECCXX
#  else
#   define ossl_OPENSSL_SYS_VMS_NODECC
#  endif
# endif

/* -------------------------------- Unix ---------------------------------- */
# ifdef ossl_OPENSSL_SYS_UNIX
#  if defined(linux) || defined(__linux__) && !defined(ossl_OPENSSL_SYS_LINUX)
#   define ossl_OPENSSL_SYS_LINUX
#  endif
#  if defined(_AIX) && !defined(ossl_OPENSSL_SYS_AIX)
#   define ossl_OPENSSL_SYS_AIX
#  endif
# endif

/* -------------------------------- VOS ----------------------------------- */
# if defined(__VOS__) && !defined(ossl_OPENSSL_SYS_VOS)
#  define ossl_OPENSSL_SYS_VOS
#  ifdef __HPPA__
#   define ossl_OPENSSL_SYS_VOS_HPPA
#  endif
#  ifdef __IA32__
#   define ossl_OPENSSL_SYS_VOS_IA32
#  endif
# endif

/* ---------------------------- HP NonStop -------------------------------- */
# ifdef __TANDEM
#  ifdef _STRING
#   include <strings.h>
#  endif
# define ossl_OPENSSL_USE_BUILD_DATE
# if defined(ossl_OPENSSL_THREADS) && defined(_SPT_MODEL_)
#  define  SPT_THREAD_SIGNAL 1
#  define  SPT_THREAD_AWARE 1
#  include <spthread.h>
# elif defined(ossl_OPENSSL_THREADS) && defined(_PUT_MODEL_)
#  include <pthread.h>
# endif
# endif

/**
 * That's it for OS-specific stuff
 *****************************************************************************/

/*-
 * ossl_OPENSSL_EXTERN is normally used to declare a symbol with possible extra
 * attributes to handle its presence in a shared library.
 * ossl_OPENSSL_EXPORT is used to define a symbol with extra possible attributes
 * to make it visible in a shared library.
 * Care needs to be taken when a header file is used both to declare and
 * define symbols.  Basically, for any library that exports some global
 * variables, the following code must be present in the header file that
 * declares them, before ossl_OPENSSL_EXTERN is used:
 *
 * #ifdef SOME_BUILD_FLAG_MACRO
 * # undef ossl_OPENSSL_EXTERN
 * # define ossl_OPENSSL_EXTERN ossl_OPENSSL_EXPORT
 * #endif
 *
 * The default is to have ossl_OPENSSL_EXPORT and ossl_OPENSSL_EXTERN
 * have some generally sensible values.
 */

# if defined(ossl_OPENSSL_SYS_WINDOWS) && defined(ossl_OPENSSL_OPT_WINDLL)
#  define ossl_OPENSSL_EXPORT extern __declspec(dllexport)
#  define ossl_OPENSSL_EXTERN extern __declspec(dllimport)
# else
#  define ossl_OPENSSL_EXPORT extern
#  define ossl_OPENSSL_EXTERN extern
# endif

# ifdef _WIN32
#  ifdef _WIN64
#   define ossl_ossl_ssize_t __int64
#   define ossl_OSSL_SSIZE_MAX _I64_MAX
#  else
#   define ossl_ossl_ssize_t int
#   define ossl_OSSL_SSIZE_MAX INT_MAX
#  endif
# endif

# if defined(ossl_OPENSSL_SYS_UEFI) && !defined(ossl_ossl_ssize_t)
#  define ossl_ossl_ssize_t INTN
#  define ossl_OSSL_SSIZE_MAX MAX_INTN
# endif

# ifndef ossl_ossl_ssize_t
#  define ossl_ossl_ssize_t ssize_t
#  if defined(SSIZE_MAX)
#   define ossl_OSSL_SSIZE_MAX SSIZE_MAX
#  elif defined(_POSIX_SSIZE_MAX)
#   define ossl_OSSL_SSIZE_MAX _POSIX_SSIZE_MAX
#  else
#   define ossl_OSSL_SSIZE_MAX ((ssize_t)(SIZE_MAX>>1))
#  endif
# endif

# if defined(UNUSEDRESULT_DEBUG)
#  define ossl___owur __attribute__((__warn_unused_result__))
# else
#  define ossl___owur
# endif

/* Standard integer types */
# define ossl_OPENSSL_NO_INTTYPES_H
# define ossl_OPENSSL_NO_STDINT_H
# if defined(ossl_OPENSSL_SYS_UEFI)
typedef INT8 int8_t;
typedef UINT8 uint8_t;
typedef INT16 int16_t;
typedef UINT16 uint16_t;
typedef INT32 int32_t;
typedef UINT32 uint32_t;
typedef INT64 int64_t;
typedef UINT64 uint64_t;
# elif (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L) || \
     defined(__osf__) || defined(__sgi) || defined(__hpux) || \
     defined(ossl_OPENSSL_SYS_VMS) || defined (__OpenBSD__)
#  include <inttypes.h>
#  undef ossl_OPENSSL_NO_INTTYPES_H
/* Because the specs say that inttypes.h includes stdint.h if present */
#  undef ossl_OPENSSL_NO_STDINT_H
# elif defined(_MSC_VER) && _MSC_VER<1600
/*
 * minimally required typdefs for systems not supporting inttypes.h or
 * stdint.h: currently just older VC++
 */
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
# else
#  include <stdint.h>
#  undef ossl_OPENSSL_NO_STDINT_H
# endif
# if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L && \
    defined(INTMAX_MAX) && defined(UINTMAX_MAX)
typedef intmax_t ossl_ossl_intmax_t;
typedef uintmax_t ossl_ossl_uintmax_t;
# else
/* Fall back to the largest we know we require and can handle */
typedef int64_t ossl_ossl_intmax_t;
typedef uint64_t ossl_ossl_uintmax_t;
# endif

/* ossl_ossl_inline: portable inline definition usable in public headers */
# if !defined(inline) && !defined(__cplusplus)
#  if defined(__STDC_VERSION__) && __STDC_VERSION__>=199901L
   /* just use inline */
#   define ossl_ossl_inline inline
#  elif defined(__GNUC__) && __GNUC__>=2
#   define ossl_ossl_inline __inline__
#  elif defined(_MSC_VER)
  /*
   * Visual Studio: inline is available in C++ only, however
   * __inline is available for C, see
   * http://msdn.microsoft.com/en-us/library/z8y1yy88.aspx
   */
#   define ossl_ossl_inline __inline
#  else
#   define ossl_ossl_inline
#  endif
# else
#  define ossl_ossl_inline inline
# endif

# if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && \
     !defined(__cplusplus) 
#  define ossl_ossl_noreturn _Noreturn
# elif defined(__GNUC__) && __GNUC__ >= 2
#  define ossl_ossl_noreturn __attribute__((noreturn))
# else
#  define ossl_ossl_noreturn
# endif

/* ossl_ossl_unused: portable unused attribute for use in public headers */
# if defined(__GNUC__)
#  define ossl_ossl_unused __attribute__((unused))
# else
#  define ossl_ossl_unused
# endif

#ifdef  __cplusplus
}
#endif
#endif
