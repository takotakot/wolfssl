/* api.c API unit tests
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */


/*----------------------------------------------------------------------------*
 | Includes
 *----------------------------------------------------------------------------*/

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_STATIC_MEMORY)
    #include <wolfssl/wolfcrypt/memory.h>
#endif /* WOLFSSL_STATIC_MEMORY */
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>   /* wc_ecc_fp_free */
#endif
#ifndef NO_ASN
    #include <wolfssl/wolfcrypt/asn_public.h>
#endif
#include <wolfssl/error-ssl.h>

#include <stdlib.h>
#include <wolfssl/ssl.h>  /* compatibility layer */
#include <wolfssl/test.h>
#include <tests/unit.h>

#ifdef OPENSSL_EXTRA
    #include <wolfssl/openssl/ssl.h>
    #include <wolfssl/openssl/crypto.h>
    #include <wolfssl/openssl/pkcs12.h>
    #include <wolfssl/openssl/evp.h>
    #include <wolfssl/openssl/dh.h>
    #include <wolfssl/openssl/bn.h>
    #include <wolfssl/openssl/buffer.h>
    #include <wolfssl/openssl/pem.h>
    #include <wolfssl/openssl/engine.h>
    #include <wolfssl/openssl/crypto.h>
    #include <wolfssl/openssl/hmac.h>
    #include <wolfssl/openssl/objects.h>
#ifndef NO_DES3
    #include <wolfssl/openssl/des.h>
#endif
#endif /* OPENSSL_EXTRA */

/* enable testing buffer load functions */
#ifndef USE_CERT_BUFFERS_2048
    #define USE_CERT_BUFFERS_2048
#endif
#include <wolfssl/certs_test.h>

/*----------------------------------------------------------------------------*
 | Constants
 *----------------------------------------------------------------------------*/

#define TEST_SUCCESS    (1)
#define TEST_FAIL       (0)

#define testingFmt "   %s:"
#define resultFmt  " %s\n"
static const char* passed = "passed";
static const char* failed = "failed";

#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
    static const char* bogusFile  =
    #ifdef _WIN32
        "NUL"
    #else
        "/dev/null"
    #endif
    ;
#endif

/*----------------------------------------------------------------------------*
 | Setup
 *----------------------------------------------------------------------------*/

static int test_wolfSSL_Init(void)
{
    int result;

    printf(testingFmt, "wolfSSL_Init()");
    result = wolfSSL_Init();
    printf(resultFmt, result == SSL_SUCCESS ? passed : failed);

    return result;
}


static int test_wolfSSL_Cleanup(void)
{
    int result;

    printf(testingFmt, "wolfSSL_Cleanup()");
    result = wolfSSL_Cleanup();
    printf(resultFmt, result == SSL_SUCCESS ? passed : failed);

    return result;
}


/*  Initialize the wolfCrypt state.
 *  POST: 0 success.
 */
static int test_wolfCrypt_Init(void)
{
    int result;

    printf(testingFmt, "wolfCrypt_Init()");
    result = wolfCrypt_Init();
    printf(resultFmt, result == 0 ? passed : failed);

    return result;

} /* END test_wolfCrypt_Init */

/*----------------------------------------------------------------------------*
 | Method Allocators
 *----------------------------------------------------------------------------*/

static void test_wolfSSL_Method_Allocators(void)
{
    #define TEST_METHOD_ALLOCATOR(allocator, condition) \
        do {                                            \
            WOLFSSL_METHOD *method;                      \
            condition(method = allocator());            \
            XFREE(method, 0, DYNAMIC_TYPE_METHOD);      \
        } while(0)

    #define TEST_VALID_METHOD_ALLOCATOR(a) \
            TEST_METHOD_ALLOCATOR(a, AssertNotNull)

    #define TEST_INVALID_METHOD_ALLOCATOR(a) \
            TEST_METHOD_ALLOCATOR(a, AssertNull)

#ifndef NO_OLD_TLS
    #ifdef WOLFSSL_ALLOW_SSLV3
        TEST_VALID_METHOD_ALLOCATOR(wolfSSLv3_server_method);
        TEST_VALID_METHOD_ALLOCATOR(wolfSSLv3_client_method);
    #endif
    TEST_VALID_METHOD_ALLOCATOR(wolfTLSv1_server_method);
    TEST_VALID_METHOD_ALLOCATOR(wolfTLSv1_client_method);
    TEST_VALID_METHOD_ALLOCATOR(wolfTLSv1_1_server_method);
    TEST_VALID_METHOD_ALLOCATOR(wolfTLSv1_1_client_method);
#endif
    TEST_VALID_METHOD_ALLOCATOR(wolfTLSv1_2_server_method);
    TEST_VALID_METHOD_ALLOCATOR(wolfTLSv1_2_client_method);
    TEST_VALID_METHOD_ALLOCATOR(wolfSSLv23_client_method);

#ifdef WOLFSSL_DTLS
    #ifndef NO_OLD_TLS
        TEST_VALID_METHOD_ALLOCATOR(wolfDTLSv1_server_method);
        TEST_VALID_METHOD_ALLOCATOR(wolfDTLSv1_client_method);
    #endif
    TEST_VALID_METHOD_ALLOCATOR(wolfDTLSv1_2_server_method);
    TEST_VALID_METHOD_ALLOCATOR(wolfDTLSv1_2_client_method);
#endif

#ifdef OPENSSL_EXTRA
    TEST_INVALID_METHOD_ALLOCATOR(wolfSSLv2_server_method);
    TEST_INVALID_METHOD_ALLOCATOR(wolfSSLv2_client_method);
#endif
}

/*----------------------------------------------------------------------------*
 | Context
 *----------------------------------------------------------------------------*/

static void test_wolfSSL_CTX_new(WOLFSSL_METHOD *method)
{
    WOLFSSL_CTX *ctx;

    AssertNull(ctx = wolfSSL_CTX_new(NULL));

    AssertNotNull(method);
    AssertNotNull(ctx = wolfSSL_CTX_new(method));

    wolfSSL_CTX_free(ctx);
}


static void test_wolfSSL_CTX_use_certificate_file(void)
{
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
    WOLFSSL_CTX *ctx;

    AssertNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));

    /* invalid context */
    AssertFalse(wolfSSL_CTX_use_certificate_file(NULL, svrCert,
                                                             SSL_FILETYPE_PEM));
    /* invalid cert file */
    AssertFalse(wolfSSL_CTX_use_certificate_file(ctx, bogusFile,
                                                             SSL_FILETYPE_PEM));
    /* invalid cert type */
    AssertFalse(wolfSSL_CTX_use_certificate_file(ctx, svrCert, 9999));

#ifdef NO_RSA
    /* rsa needed */
    AssertFalse(wolfSSL_CTX_use_certificate_file(ctx, svrCert,SSL_FILETYPE_PEM));
#else
    /* success */
    AssertTrue(wolfSSL_CTX_use_certificate_file(ctx, svrCert, SSL_FILETYPE_PEM));
#endif

    wolfSSL_CTX_free(ctx);
#endif
}

/*  Test function for wolfSSL_CTX_use_certificate_buffer. Load cert into
 *  context using buffer.
 *  PRE: NO_CERTS not defined; USE_CERT_BUFFERS_2048 defined; compile with
 *  --enable-testcert flag.
 */
static int test_wolfSSL_CTX_use_certificate_buffer(void)
{
    #if !defined(NO_CERTS) && defined(USE_CERT_BUFFERS_2048) && !defined(NO_RSA)
        WOLFSSL_CTX*            ctx;
        int                     ret;

        printf(testingFmt, "wolfSSL_CTX_use_certificate_buffer()");
        AssertNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));

        ret = wolfSSL_CTX_use_certificate_buffer(ctx, server_cert_der_2048,
                    sizeof_server_cert_der_2048, SSL_FILETYPE_ASN1);

        printf(resultFmt, ret == SSL_SUCCESS ? passed : failed);
        wolfSSL_CTX_free(ctx);

        return ret;
    #else
        return SSL_SUCCESS;
    #endif

} /*END test_wolfSSL_CTX_use_certificate_buffer*/

static void test_wolfSSL_CTX_use_PrivateKey_file(void)
{
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
    WOLFSSL_CTX *ctx;

    AssertNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));

    /* invalid context */
    AssertFalse(wolfSSL_CTX_use_PrivateKey_file(NULL, svrKey,
                                                             SSL_FILETYPE_PEM));
    /* invalid key file */
    AssertFalse(wolfSSL_CTX_use_PrivateKey_file(ctx, bogusFile,
                                                             SSL_FILETYPE_PEM));
    /* invalid key type */
    AssertFalse(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKey, 9999));

    /* success */
#ifdef NO_RSA
    /* rsa needed */
    AssertFalse(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKey, SSL_FILETYPE_PEM));
#else
    /* success */
    AssertTrue(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKey, SSL_FILETYPE_PEM));
#endif

    wolfSSL_CTX_free(ctx);
#endif
}


/* test both file and buffer versions along with unloading trusted peer certs */
static void test_wolfSSL_CTX_trust_peer_cert(void)
{
#if !defined(NO_CERTS) && defined(WOLFSSL_TRUST_PEER_CERT)
    WOLFSSL_CTX *ctx;

    AssertNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));

#if !defined(NO_FILESYSTEM)
    /* invalid file */
    assert(wolfSSL_CTX_trust_peer_cert(ctx, NULL,
                                              SSL_FILETYPE_PEM) != SSL_SUCCESS);
    assert(wolfSSL_CTX_trust_peer_cert(ctx, bogusFile,
                                              SSL_FILETYPE_PEM) != SSL_SUCCESS);
    assert(wolfSSL_CTX_trust_peer_cert(ctx, cliCert,
                                             SSL_FILETYPE_ASN1) != SSL_SUCCESS);

    /* success */
    assert(wolfSSL_CTX_trust_peer_cert(ctx, cliCert, SSL_FILETYPE_PEM)
                                                                == SSL_SUCCESS);

    /* unload cert */
    assert(wolfSSL_CTX_Unload_trust_peers(NULL) != SSL_SUCCESS);
    assert(wolfSSL_CTX_Unload_trust_peers(ctx) == SSL_SUCCESS);
#endif

    /* Test of loading certs from buffers */

    /* invalid buffer */
    assert(wolfSSL_CTX_trust_peer_buffer(ctx, NULL, -1,
                                             SSL_FILETYPE_ASN1) != SSL_SUCCESS);

    /* success */
#ifdef USE_CERT_BUFFERS_1024
    assert(wolfSSL_CTX_trust_peer_buffer(ctx, client_cert_der_1024,
                sizeof_client_cert_der_1024, SSL_FILETYPE_ASN1) == SSL_SUCCESS);
#endif
#ifdef USE_CERT_BUFFERS_2048
    assert(wolfSSL_CTX_trust_peer_buffer(ctx, client_cert_der_2048,
                sizeof_client_cert_der_2048, SSL_FILETYPE_ASN1) == SSL_SUCCESS);
#endif

    /* unload cert */
    assert(wolfSSL_CTX_Unload_trust_peers(NULL) != SSL_SUCCESS);
    assert(wolfSSL_CTX_Unload_trust_peers(ctx) == SSL_SUCCESS);

    wolfSSL_CTX_free(ctx);
#endif
}


static void test_wolfSSL_CTX_load_verify_locations(void)
{
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
    WOLFSSL_CTX *ctx;

    AssertNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));

    /* invalid context */
    AssertFalse(wolfSSL_CTX_load_verify_locations(NULL, caCert, 0));

    /* invalid ca file */
    AssertFalse(wolfSSL_CTX_load_verify_locations(ctx, NULL,      0));
    AssertFalse(wolfSSL_CTX_load_verify_locations(ctx, bogusFile, 0));

#ifndef WOLFSSL_TIRTOS
    /* invalid path */
    /* not working... investigate! */
    /* AssertFalse(wolfSSL_CTX_load_verify_locations(ctx, caCert, bogusFile)); */
#endif

    /* success */
    AssertTrue(wolfSSL_CTX_load_verify_locations(ctx, caCert, 0));

    wolfSSL_CTX_free(ctx);
#endif
}

static void test_wolfSSL_CTX_SetTmpDH_file(void)
{
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && !defined(NO_DH)
    WOLFSSL_CTX *ctx;

    AssertNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));

    /* invalid context */
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_SetTmpDH_file(NULL,
                dhParam, SSL_FILETYPE_PEM));

    /* invalid dhParam file */
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_SetTmpDH_file(ctx,
                NULL, SSL_FILETYPE_PEM));
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_SetTmpDH_file(ctx,
                bogusFile, SSL_FILETYPE_PEM));

    /* success */
    AssertIntEQ(SSL_SUCCESS, wolfSSL_CTX_SetTmpDH_file(ctx, dhParam,
                SSL_FILETYPE_PEM));

    wolfSSL_CTX_free(ctx);
#endif
}

static void test_wolfSSL_CTX_SetTmpDH_buffer(void)
{
#if !defined(NO_CERTS) && !defined(NO_DH)
    WOLFSSL_CTX *ctx;

    AssertNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));

    /* invalid context */
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_SetTmpDH_buffer(NULL, dh_key_der_2048,
                sizeof_dh_key_der_2048, SSL_FILETYPE_ASN1));

    /* invalid dhParam file */
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_SetTmpDH_buffer(NULL, NULL,
                0, SSL_FILETYPE_ASN1));
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_SetTmpDH_buffer(ctx, dsa_key_der_2048,
                sizeof_dsa_key_der_2048, SSL_FILETYPE_ASN1));

    /* success */
    AssertIntEQ(SSL_SUCCESS, wolfSSL_CTX_SetTmpDH_buffer(ctx, dh_key_der_2048,
                sizeof_dh_key_der_2048, SSL_FILETYPE_ASN1));

    wolfSSL_CTX_free(ctx);
#endif
}

/*----------------------------------------------------------------------------*
 | SSL
 *----------------------------------------------------------------------------*/

static void test_server_wolfSSL_new(void)
{
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && !defined(NO_RSA)
    WOLFSSL_CTX *ctx;
    WOLFSSL_CTX *ctx_nocert;
    WOLFSSL *ssl;

    AssertNotNull(ctx_nocert = wolfSSL_CTX_new(wolfSSLv23_server_method()));
    AssertNotNull(ctx        = wolfSSL_CTX_new(wolfSSLv23_server_method()));

    AssertTrue(wolfSSL_CTX_use_certificate_file(ctx, svrCert, SSL_FILETYPE_PEM));
    AssertTrue(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKey, SSL_FILETYPE_PEM));

    /* invalid context */
    AssertNull(ssl = wolfSSL_new(NULL));
#ifndef WOLFSSL_SESSION_EXPORT
    AssertNull(ssl = wolfSSL_new(ctx_nocert));
#endif

    /* success */
    AssertNotNull(ssl = wolfSSL_new(ctx));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_CTX_free(ctx_nocert);
#endif
}


static void test_client_wolfSSL_new(void)
{
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && !defined(NO_RSA)
    WOLFSSL_CTX *ctx;
    WOLFSSL_CTX *ctx_nocert;
    WOLFSSL *ssl;

    AssertNotNull(ctx_nocert = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    AssertNotNull(ctx        = wolfSSL_CTX_new(wolfSSLv23_client_method()));

    AssertTrue(wolfSSL_CTX_load_verify_locations(ctx, caCert, 0));

    /* invalid context */
    AssertNull(ssl = wolfSSL_new(NULL));

    /* success */
    AssertNotNull(ssl = wolfSSL_new(ctx_nocert));
    wolfSSL_free(ssl);

    /* success */
    AssertNotNull(ssl = wolfSSL_new(ctx));
    wolfSSL_free(ssl);

    wolfSSL_CTX_free(ctx);
    wolfSSL_CTX_free(ctx_nocert);
#endif
}

static void test_wolfSSL_SetTmpDH_file(void)
{
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && !defined(NO_DH)
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;

    AssertNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));
#ifndef NO_RSA
    AssertTrue(wolfSSL_CTX_use_certificate_file(ctx, svrCert,
                SSL_FILETYPE_PEM));
    AssertTrue(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKey,
                SSL_FILETYPE_PEM));
#else
    AssertTrue(wolfSSL_CTX_use_certificate_file(ctx, eccCert,
                SSL_FILETYPE_PEM));
    AssertTrue(wolfSSL_CTX_use_PrivateKey_file(ctx, eccKey,
                SSL_FILETYPE_PEM));
#endif
    AssertNotNull(ssl = wolfSSL_new(ctx));

    /* invalid ssl */
    AssertIntNE(SSL_SUCCESS, wolfSSL_SetTmpDH_file(NULL,
                dhParam, SSL_FILETYPE_PEM));

    /* invalid dhParam file */
    AssertIntNE(SSL_SUCCESS, wolfSSL_SetTmpDH_file(ssl,
                NULL, SSL_FILETYPE_PEM));
    AssertIntNE(SSL_SUCCESS, wolfSSL_SetTmpDH_file(ssl,
                bogusFile, SSL_FILETYPE_PEM));

    /* success */
    AssertIntEQ(SSL_SUCCESS, wolfSSL_SetTmpDH_file(ssl, dhParam,
                SSL_FILETYPE_PEM));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
}

static void test_wolfSSL_SetTmpDH_buffer(void)
{
#if !defined(NO_CERTS) && !defined(NO_DH)
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;

    AssertNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));
    AssertTrue(wolfSSL_CTX_use_certificate_buffer(ctx, server_cert_der_2048,
                sizeof_server_cert_der_2048, SSL_FILETYPE_ASN1));
    AssertTrue(wolfSSL_CTX_use_PrivateKey_buffer(ctx, server_key_der_2048,
                sizeof_server_key_der_2048, SSL_FILETYPE_ASN1));
    AssertNotNull(ssl = wolfSSL_new(ctx));

    /* invalid ssl */
    AssertIntNE(SSL_SUCCESS, wolfSSL_SetTmpDH_buffer(NULL, dh_key_der_2048,
                sizeof_dh_key_der_2048, SSL_FILETYPE_ASN1));

    /* invalid dhParam file */
    AssertIntNE(SSL_SUCCESS, wolfSSL_SetTmpDH_buffer(NULL, NULL,
                0, SSL_FILETYPE_ASN1));
    AssertIntNE(SSL_SUCCESS, wolfSSL_SetTmpDH_buffer(ssl, dsa_key_der_2048,
                sizeof_dsa_key_der_2048, SSL_FILETYPE_ASN1));

    /* success */
    AssertIntEQ(SSL_SUCCESS, wolfSSL_SetTmpDH_buffer(ssl, dh_key_der_2048,
                sizeof_dh_key_der_2048, SSL_FILETYPE_ASN1));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
}


/* Test function for wolfSSL_SetMinVersion. Sets the minimum downgrade version
 * allowed.
 * POST: return 1 on success.
 */
static int test_wolfSSL_SetMinVersion(void)
{
    WOLFSSL_CTX*        ctx;
    WOLFSSL*            ssl;
    int                 failFlag, itr;

    #ifndef NO_OLD_TLS
        const int versions[]  =  { WOLFSSL_TLSV1, WOLFSSL_TLSV1_1,
                                  WOLFSSL_TLSV1_2};
    #else
        const int versions[]  =  { WOLFSSL_TLSV1_2 };
    #endif
    failFlag = SSL_SUCCESS;

    AssertTrue(wolfSSL_Init());
    ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    ssl = wolfSSL_new(ctx);

    printf(testingFmt, "wolfSSL_SetMinVersion()");

    for (itr = 0; itr < (int)(sizeof(versions)/sizeof(int)); itr++){
       if(wolfSSL_SetMinVersion(ssl, *(versions + itr)) != SSL_SUCCESS){
            failFlag = SSL_FAILURE;
        }
    }

    printf(resultFmt, failFlag == SSL_SUCCESS ? passed : failed);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    AssertTrue(wolfSSL_Cleanup());

    return failFlag;

} /* END test_wolfSSL_SetMinVersion */


/*----------------------------------------------------------------------------*
 | IO
 *----------------------------------------------------------------------------*/
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && \
    !defined(NO_RSA)        && !defined(SINGLE_THREADED)
#define HAVE_IO_TESTS_DEPENDENCIES
#endif

/* helper functions */
#ifdef HAVE_IO_TESTS_DEPENDENCIES
#ifdef WOLFSSL_SESSION_EXPORT
/* set up function for sending session information */
static int test_export(WOLFSSL* inSsl, byte* buf, word32 sz, void* userCtx)
{
    WOLFSSL_CTX* ctx;
    WOLFSSL*     ssl;

    AssertNotNull(inSsl);
    AssertNotNull(buf);
    AssertIntNE(0, sz);

    /* Set ctx to DTLS 1.2 */
    ctx = wolfSSL_CTX_new(wolfDTLSv1_2_server_method());
    AssertNotNull(ctx);

    ssl = wolfSSL_new(ctx);
    AssertNotNull(ssl);

    AssertIntGE(wolfSSL_dtls_import(ssl, buf, sz), 0);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    (void)userCtx;
    return SSL_SUCCESS;
}
#endif


static THREAD_RETURN WOLFSSL_THREAD test_server_nofail(void* args)
{
    SOCKET_T sockfd = 0;
    SOCKET_T clientfd = 0;
    word16 port;

    WOLFSSL_METHOD* method = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;

    char msg[] = "I hear you fa shizzle!";
    char input[1024];
    int idx;
    int ret, err = 0;

#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif

    ((func_args*)args)->return_code = TEST_FAIL;
    if (((func_args*)args)->callbacks != NULL &&
        ((func_args*)args)->callbacks->method != NULL) {
        method = ((func_args*)args)->callbacks->method();
    }
    else {
        method = wolfSSLv23_server_method();
    }
    ctx = wolfSSL_CTX_new(method);

#if defined(USE_WINDOWS_API)
    port = ((func_args*)args)->signal->port;
#elif defined(NO_MAIN_DRIVER) && !defined(WOLFSSL_SNIFFER) && \
     !defined(WOLFSSL_MDK_SHELL) && !defined(WOLFSSL_TIRTOS)
    /* Let tcp_listen assign port */
    port = 0;
#else
    /* Use default port */
    port = wolfSSLPort;
#endif

    wolfSSL_CTX_set_verify(ctx,
                          SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);

#ifdef OPENSSL_EXTRA
    wolfSSL_CTX_set_default_passwd_cb(ctx, PasswordCallBack);
#endif

    if (wolfSSL_CTX_load_verify_locations(ctx, cliCert, 0) != SSL_SUCCESS)
    {
        /*err_sys("can't load ca file, Please run from wolfSSL home dir");*/
        goto done;
    }
    if (wolfSSL_CTX_use_certificate_file(ctx, svrCert, SSL_FILETYPE_PEM)
            != SSL_SUCCESS)
    {
        /*err_sys("can't load server cert chain file, "
                "Please run from wolfSSL home dir");*/
        goto done;
    }
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, svrKey, SSL_FILETYPE_PEM)
            != SSL_SUCCESS)
    {
        /*err_sys("can't load server key file, "
                "Please run from wolfSSL home dir");*/
        goto done;
    }

    ssl = wolfSSL_new(ctx);
    tcp_accept(&sockfd, &clientfd, (func_args*)args, port, 0, 0, 0, 0, 1);
    CloseSocket(sockfd);

    if (wolfSSL_set_fd(ssl, clientfd) != SSL_SUCCESS) {
        /*err_sys("SSL_set_fd failed");*/
        goto done;
    }

#ifdef NO_PSK
    #if !defined(NO_FILESYSTEM) && !defined(NO_DH)
        wolfSSL_SetTmpDH_file(ssl, dhParam, SSL_FILETYPE_PEM);
    #elif !defined(NO_DH)
        SetDH(ssl);  /* will repick suites with DHE, higher priority than PSK */
    #endif
#endif

    do {
#ifdef WOLFSSL_ASYNC_CRYPT
        if (err == WC_PENDING_E) {
            ret = wolfSSL_AsyncPoll(ssl, WOLF_POLL_FLAG_CHECK_HW);
            if (ret < 0) { break; } else if (ret == 0) { continue; }
        }
#endif

        err = 0; /* Reset error */
        ret = wolfSSL_accept(ssl);
        if (ret != SSL_SUCCESS) {
            err = wolfSSL_get_error(ssl, 0);
        }
    } while (ret != SSL_SUCCESS && err == WC_PENDING_E);

    if (ret != SSL_SUCCESS) {
        char buffer[WOLFSSL_MAX_ERROR_SZ];
        printf("error = %d, %s\n", err, wolfSSL_ERR_error_string(err, buffer));
        /*err_sys("SSL_accept failed");*/
        goto done;
    }

    idx = wolfSSL_read(ssl, input, sizeof(input)-1);
    if (idx > 0) {
        input[idx] = 0;
        printf("Client message: %s\n", input);
    }

    if (wolfSSL_write(ssl, msg, sizeof(msg)) != sizeof(msg))
    {
        /*err_sys("SSL_write failed");*/
#ifdef WOLFSSL_TIRTOS
        return;
#else
        return 0;
#endif
    }

#ifdef WOLFSSL_TIRTOS
    Task_yield();
#endif

done:
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    CloseSocket(clientfd);
    ((func_args*)args)->return_code = TEST_SUCCESS;

#ifdef WOLFSSL_TIRTOS
    fdCloseSession(Task_self());
#endif

#if defined(NO_MAIN_DRIVER) && defined(HAVE_ECC) && defined(FP_ECC) \
                            && defined(HAVE_THREAD_LS)
    wc_ecc_fp_free();  /* free per thread cache */
#endif

#ifndef WOLFSSL_TIRTOS
    return 0;
#endif
}


static void test_client_nofail(void* args)
{
    SOCKET_T sockfd = 0;

    WOLFSSL_METHOD*  method  = 0;
    WOLFSSL_CTX*     ctx     = 0;
    WOLFSSL*         ssl     = 0;

    char msg[64] = "hello wolfssl!";
    char reply[1024];
    int  input;
    int  msgSz = (int)XSTRLEN(msg);
    int  ret, err = 0;

#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif

    ((func_args*)args)->return_code = TEST_FAIL;
    if (((func_args*)args)->callbacks != NULL &&
        ((func_args*)args)->callbacks->method != NULL) {
        method = ((func_args*)args)->callbacks->method();
    }
    else {
        method = wolfSSLv23_client_method();
    }
    ctx = wolfSSL_CTX_new(method);

#ifdef OPENSSL_EXTRA
    wolfSSL_CTX_set_default_passwd_cb(ctx, PasswordCallBack);
#endif

    if (wolfSSL_CTX_load_verify_locations(ctx, caCert, 0) != SSL_SUCCESS)
    {
        /* err_sys("can't load ca file, Please run from wolfSSL home dir");*/
        goto done2;
    }
    if (wolfSSL_CTX_use_certificate_file(ctx, cliCert, SSL_FILETYPE_PEM)
            != SSL_SUCCESS)
    {
        /*err_sys("can't load client cert file, "
                "Please run from wolfSSL home dir");*/
        goto done2;
    }
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, cliKey, SSL_FILETYPE_PEM)
            != SSL_SUCCESS)
    {
        /*err_sys("can't load client key file, "
                "Please run from wolfSSL home dir");*/
        goto done2;
    }

    ssl = wolfSSL_new(ctx);
    tcp_connect(&sockfd, wolfSSLIP, ((func_args*)args)->signal->port,
                0, 0, ssl);
    if (wolfSSL_set_fd(ssl, sockfd) != SSL_SUCCESS) {
        /*err_sys("SSL_set_fd failed");*/
        goto done2;
    }

    do {
#ifdef WOLFSSL_ASYNC_CRYPT
        if (err == WC_PENDING_E) {
            ret = wolfSSL_AsyncPoll(ssl, WOLF_POLL_FLAG_CHECK_HW);
            if (ret < 0) { break; } else if (ret == 0) { continue; }
        }
#endif

        err = 0; /* Reset error */
        ret = wolfSSL_connect(ssl);
        if (ret != SSL_SUCCESS) {
            err = wolfSSL_get_error(ssl, 0);
        }
    } while (ret != SSL_SUCCESS && err == WC_PENDING_E);

    if (ret != SSL_SUCCESS) {
        char buffer[WOLFSSL_MAX_ERROR_SZ];
        printf("error = %d, %s\n", err, wolfSSL_ERR_error_string(err, buffer));
        /*err_sys("SSL_connect failed");*/
        goto done2;
    }

    if (wolfSSL_write(ssl, msg, msgSz) != msgSz)
    {
        /*err_sys("SSL_write failed");*/
        goto done2;
    }

    input = wolfSSL_read(ssl, reply, sizeof(reply)-1);
    if (input > 0)
    {
        reply[input] = 0;
        printf("Server response: %s\n", reply);
    }

done2:
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    CloseSocket(sockfd);
    ((func_args*)args)->return_code = TEST_SUCCESS;

#ifdef WOLFSSL_TIRTOS
    fdCloseSession(Task_self());
#endif

    return;
}

/* SNI / ALPN / session export helper functions */
#if defined(HAVE_SNI) || defined(HAVE_ALPN) || defined(WOLFSSL_SESSION_EXPORT)

static THREAD_RETURN WOLFSSL_THREAD run_wolfssl_server(void* args)
{
    callback_functions* callbacks = ((func_args*)args)->callbacks;

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(callbacks->method());
    WOLFSSL*     ssl = NULL;
    SOCKET_T    sfd = 0;
    SOCKET_T    cfd = 0;
    word16      port;

    char msg[] = "I hear you fa shizzle!";
    int  len   = (int) XSTRLEN(msg);
    char input[1024];
    int  idx;
    int  ret, err = 0;

#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif
    ((func_args*)args)->return_code = TEST_FAIL;

#if defined(USE_WINDOWS_API)
    port = ((func_args*)args)->signal->port;
#elif defined(NO_MAIN_DRIVER) && !defined(WOLFSSL_SNIFFER) && \
     !defined(WOLFSSL_MDK_SHELL) && !defined(WOLFSSL_TIRTOS)
    /* Let tcp_listen assign port */
    port = 0;
#else
    /* Use default port */
    port = wolfSSLPort;
#endif

    wolfSSL_CTX_set_verify(ctx,
                          SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);

#ifdef OPENSSL_EXTRA
    wolfSSL_CTX_set_default_passwd_cb(ctx, PasswordCallBack);
#endif
#ifdef WOLFSSL_SESSION_EXPORT
    AssertIntEQ(SSL_SUCCESS, wolfSSL_CTX_dtls_set_export(ctx, test_export));
#endif


    AssertIntEQ(SSL_SUCCESS, wolfSSL_CTX_load_verify_locations(ctx, cliCert, 0));

    AssertIntEQ(SSL_SUCCESS,
               wolfSSL_CTX_use_certificate_file(ctx, svrCert, SSL_FILETYPE_PEM));

    AssertIntEQ(SSL_SUCCESS,
                 wolfSSL_CTX_use_PrivateKey_file(ctx, svrKey, SSL_FILETYPE_PEM));

    if (callbacks->ctx_ready)
        callbacks->ctx_ready(ctx);

    ssl = wolfSSL_new(ctx);
    if (wolfSSL_dtls(ssl)) {
        SOCKADDR_IN_T cliAddr;
        socklen_t     cliLen;

        cliLen = sizeof(cliAddr);
        tcp_accept(&sfd, &cfd, (func_args*)args, port, 0, 1, 0, 0, 0);
        idx = (int)recvfrom(sfd, input, sizeof(input), MSG_PEEK,
                (struct sockaddr*)&cliAddr, &cliLen);
        AssertIntGT(idx, 0);
        wolfSSL_dtls_set_peer(ssl, &cliAddr, cliLen);
    }
    else {
        tcp_accept(&sfd, &cfd, (func_args*)args, port, 0, 0, 0, 0, 1);
        CloseSocket(sfd);
    }

    AssertIntEQ(SSL_SUCCESS, wolfSSL_set_fd(ssl, cfd));

#ifdef NO_PSK
    #if !defined(NO_FILESYSTEM) && !defined(NO_DH)
        wolfSSL_SetTmpDH_file(ssl, dhParam, SSL_FILETYPE_PEM);
    #elif !defined(NO_DH)
        SetDH(ssl);  /* will repick suites with DHE, higher priority than PSK */
    #endif
#endif

    if (callbacks->ssl_ready)
        callbacks->ssl_ready(ssl);

    do {
#ifdef WOLFSSL_ASYNC_CRYPT
        if (err == WC_PENDING_E) {
            ret = wolfSSL_AsyncPoll(ssl, WOLF_POLL_FLAG_CHECK_HW);
            if (ret < 0) { break; } else if (ret == 0) { continue; }
        }
#endif

        err = 0; /* Reset error */
        ret = wolfSSL_accept(ssl);
        if (ret != SSL_SUCCESS) {
            err = wolfSSL_get_error(ssl, 0);
        }
    } while (ret != SSL_SUCCESS && err == WC_PENDING_E);

    if (ret != SSL_SUCCESS) {
        char buffer[WOLFSSL_MAX_ERROR_SZ];
        printf("error = %d, %s\n", err, wolfSSL_ERR_error_string(err, buffer));
        /*err_sys("SSL_accept failed");*/
    }
    else {
        if (0 < (idx = wolfSSL_read(ssl, input, sizeof(input)-1))) {
            input[idx] = 0;
            printf("Client message: %s\n", input);
        }

        AssertIntEQ(len, wolfSSL_write(ssl, msg, len));
#if defined(WOLFSSL_SESSION_EXPORT) && !defined(HAVE_IO_POOL)
        if (wolfSSL_dtls(ssl)) {
            byte*  import;
            word32 sz;

            wolfSSL_dtls_export(ssl, NULL, &sz);
            import = (byte*)XMALLOC(sz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            AssertNotNull(import);
            idx = wolfSSL_dtls_export(ssl, import, &sz);
            AssertIntGE(idx, 0);
            AssertIntGE(wolfSSL_dtls_import(ssl, import, idx), 0);
            XFREE(import, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
#endif
#ifdef WOLFSSL_TIRTOS
        Task_yield();
#endif
        wolfSSL_shutdown(ssl);
    }

    if (callbacks->on_result)
        callbacks->on_result(ssl);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    CloseSocket(cfd);

    ((func_args*)args)->return_code = TEST_SUCCESS;

#ifdef WOLFSSL_TIRTOS
    fdCloseSession(Task_self());
#endif

#if defined(NO_MAIN_DRIVER) && defined(HAVE_ECC) && defined(FP_ECC) \
                            && defined(HAVE_THREAD_LS)
    wc_ecc_fp_free();  /* free per thread cache */
#endif

#ifndef WOLFSSL_TIRTOS
    return 0;
#endif
}


static void run_wolfssl_client(void* args)
{
    callback_functions* callbacks = ((func_args*)args)->callbacks;

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(callbacks->method());
    WOLFSSL*     ssl = NULL;
    SOCKET_T    sfd = 0;

    char msg[] = "hello wolfssl server!";
    int  len   = (int) XSTRLEN(msg);
    char input[1024];
    int  idx;
    int  ret, err = 0;

#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif

    ((func_args*)args)->return_code = TEST_FAIL;

#ifdef OPENSSL_EXTRA
    wolfSSL_CTX_set_default_passwd_cb(ctx, PasswordCallBack);
#endif

    AssertIntEQ(SSL_SUCCESS, wolfSSL_CTX_load_verify_locations(ctx, caCert, 0));

    AssertIntEQ(SSL_SUCCESS,
               wolfSSL_CTX_use_certificate_file(ctx, cliCert, SSL_FILETYPE_PEM));

    AssertIntEQ(SSL_SUCCESS,
                 wolfSSL_CTX_use_PrivateKey_file(ctx, cliKey, SSL_FILETYPE_PEM));

    if (callbacks->ctx_ready)
        callbacks->ctx_ready(ctx);

    ssl = wolfSSL_new(ctx);
    if (wolfSSL_dtls(ssl)) {
        tcp_connect(&sfd, wolfSSLIP, ((func_args*)args)->signal->port,
                    1, 0, ssl);
    }
    else {
        tcp_connect(&sfd, wolfSSLIP, ((func_args*)args)->signal->port,
                    0, 0, ssl);
    }
    AssertIntEQ(SSL_SUCCESS, wolfSSL_set_fd(ssl, sfd));

    if (callbacks->ssl_ready)
        callbacks->ssl_ready(ssl);

    do {
#ifdef WOLFSSL_ASYNC_CRYPT
        if (err == WC_PENDING_E) {
            ret = wolfSSL_AsyncPoll(ssl, WOLF_POLL_FLAG_CHECK_HW);
            if (ret < 0) { break; } else if (ret == 0) { continue; }
        }
#endif

        err = 0; /* Reset error */
        ret = wolfSSL_connect(ssl);
        if (ret != SSL_SUCCESS) {
            err = wolfSSL_get_error(ssl, 0);
        }
    } while (ret != SSL_SUCCESS && err == WC_PENDING_E);

    if (ret != SSL_SUCCESS) {
        char buffer[WOLFSSL_MAX_ERROR_SZ];
        printf("error = %d, %s\n", err, wolfSSL_ERR_error_string(err, buffer));
        /*err_sys("SSL_connect failed");*/
    }
    else {
        AssertIntEQ(len, wolfSSL_write(ssl, msg, len));

        if (0 < (idx = wolfSSL_read(ssl, input, sizeof(input)-1))) {
            input[idx] = 0;
            printf("Server response: %s\n", input);
        }
    }

    if (callbacks->on_result)
        callbacks->on_result(ssl);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    CloseSocket(sfd);
    ((func_args*)args)->return_code = TEST_SUCCESS;

#ifdef WOLFSSL_TIRTOS
    fdCloseSession(Task_self());
#endif
}

#endif /* defined(HAVE_SNI) || defined(HAVE_ALPN) ||
          defined(WOLFSSL_SESSION_EXPORT) */
#endif /* io tests dependencies */


static void test_wolfSSL_read_write(void)
{
#ifdef HAVE_IO_TESTS_DEPENDENCIES
    /* The unit testing for read and write shall happen simutaneously, since
     * one can't do anything with one without the other. (Except for a failure
     * test case.) This function will call all the others that will set up,
     * execute, and report their test findings.
     *
     * Set up the success case first. This function will become the template
     * for the other tests. This should eventually be renamed
     *
     * The success case isn't interesting, how can this fail?
     * - Do not give the client context a CA certificate. The connect should
     *   fail. Do not need server for this?
     * - Using NULL for the ssl object on server. Do not need client for this.
     * - Using NULL for the ssl object on client. Do not need server for this.
     * - Good ssl objects for client and server. Client write() without server
     *   read().
     * - Good ssl objects for client and server. Server write() without client
     *   read().
     * - Forgetting the password callback?
    */
    tcp_ready ready;
    func_args client_args;
    func_args server_args;
    THREAD_TYPE serverThread;

    XMEMSET(&client_args, 0, sizeof(func_args));
    XMEMSET(&server_args, 0, sizeof(func_args));
#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif

    StartTCP();
    InitTcpReady(&ready);

#if defined(USE_WINDOWS_API)
    /* use RNG to get random port if using windows */
    ready.port = GetRandomPort();
#endif

    server_args.signal = &ready;
    client_args.signal = &ready;

    start_thread(test_server_nofail, &server_args, &serverThread);
    wait_tcp_ready(&server_args);
    test_client_nofail(&client_args);
    join_thread(serverThread);

    AssertTrue(client_args.return_code);
    AssertTrue(server_args.return_code);

    FreeTcpReady(&ready);

#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif

#endif
}


static void test_wolfSSL_dtls_export(void)
{
#if defined(HAVE_IO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS) && \
    defined(WOLFSSL_SESSION_EXPORT)
    tcp_ready ready;
    func_args client_args;
    func_args server_args;
    THREAD_TYPE serverThread;
    callback_functions server_cbf;
    callback_functions client_cbf;
#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif

    InitTcpReady(&ready);

#if defined(USE_WINDOWS_API)
    /* use RNG to get random port if using windows */
    ready.port = GetRandomPort();
#endif

    /* set using dtls */
    XMEMSET(&client_args, 0, sizeof(func_args));
    XMEMSET(&server_args, 0, sizeof(func_args));
    XMEMSET(&server_cbf, 0, sizeof(callback_functions));
    XMEMSET(&client_cbf, 0, sizeof(callback_functions));
    server_cbf.method = wolfDTLSv1_2_server_method;
    client_cbf.method = wolfDTLSv1_2_client_method;
    server_args.callbacks = &server_cbf;
    client_args.callbacks = &client_cbf;

    server_args.signal = &ready;
    client_args.signal = &ready;

    start_thread(run_wolfssl_server, &server_args, &serverThread);
    wait_tcp_ready(&server_args);
    run_wolfssl_client(&client_args);
    join_thread(serverThread);

    AssertTrue(client_args.return_code);
    AssertTrue(server_args.return_code);

    FreeTcpReady(&ready);

#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif
    printf(testingFmt, "wolfSSL_dtls_export()");
    printf(resultFmt, passed);
#endif
}

/*----------------------------------------------------------------------------*
 | TLS extensions tests
 *----------------------------------------------------------------------------*/

#if defined(HAVE_SNI) || defined(HAVE_ALPN)
/* connection test runner */
static void test_wolfSSL_client_server(callback_functions* client_callbacks,
                                       callback_functions* server_callbacks)
{
#ifdef HAVE_IO_TESTS_DEPENDENCIES
    tcp_ready ready;
    func_args client_args;
    func_args server_args;
    THREAD_TYPE serverThread;

    XMEMSET(&client_args, 0, sizeof(func_args));
    XMEMSET(&server_args, 0, sizeof(func_args));

    StartTCP();

    client_args.callbacks = client_callbacks;
    server_args.callbacks = server_callbacks;

#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif

    /* RUN Server side */
    InitTcpReady(&ready);

#if defined(USE_WINDOWS_API)
    /* use RNG to get random port if using windows */
    ready.port = GetRandomPort();
#endif

    server_args.signal = &ready;
    client_args.signal = &ready;
    start_thread(run_wolfssl_server, &server_args, &serverThread);
    wait_tcp_ready(&server_args);

    /* RUN Client side */
    run_wolfssl_client(&client_args);
    join_thread(serverThread);

    FreeTcpReady(&ready);
#ifdef WOLFSSL_TIRTOS
    fdCloseSession(Task_self());
#endif

#else
    (void)client_callbacks;
    (void)server_callbacks;
#endif
}

#endif /* defined(HAVE_SNI) || defined(HAVE_ALPN) */


#ifdef HAVE_SNI
static void test_wolfSSL_UseSNI_params(void)
{
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    WOLFSSL     *ssl = wolfSSL_new(ctx);

    AssertNotNull(ctx);
    AssertNotNull(ssl);

    /* invalid [ctx|ssl] */
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_UseSNI(NULL, 0, "ctx", 3));
    AssertIntNE(SSL_SUCCESS, wolfSSL_UseSNI(    NULL, 0, "ssl", 3));
    /* invalid type */
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_UseSNI(ctx, -1, "ctx", 3));
    AssertIntNE(SSL_SUCCESS, wolfSSL_UseSNI(    ssl, -1, "ssl", 3));
    /* invalid data */
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_UseSNI(ctx,  0, NULL,  3));
    AssertIntNE(SSL_SUCCESS, wolfSSL_UseSNI(    ssl,  0, NULL,  3));
    /* success case */
    AssertIntEQ(SSL_SUCCESS, wolfSSL_CTX_UseSNI(ctx,  0, "ctx", 3));
    AssertIntEQ(SSL_SUCCESS, wolfSSL_UseSNI(    ssl,  0, "ssl", 3));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
}

/* BEGIN of connection tests callbacks */
static void use_SNI_at_ctx(WOLFSSL_CTX* ctx)
{
    AssertIntEQ(SSL_SUCCESS,
        wolfSSL_CTX_UseSNI(ctx, WOLFSSL_SNI_HOST_NAME, "www.wolfssl.com", 15));
}

static void use_SNI_at_ssl(WOLFSSL* ssl)
{
    AssertIntEQ(SSL_SUCCESS,
             wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, "www.wolfssl.com", 15));
}

static void different_SNI_at_ssl(WOLFSSL* ssl)
{
    AssertIntEQ(SSL_SUCCESS,
             wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, "ww2.wolfssl.com", 15));
}

static void use_SNI_WITH_CONTINUE_at_ssl(WOLFSSL* ssl)
{
    use_SNI_at_ssl(ssl);
    wolfSSL_SNI_SetOptions(ssl, WOLFSSL_SNI_HOST_NAME,
                                              WOLFSSL_SNI_CONTINUE_ON_MISMATCH);
}

static void use_SNI_WITH_FAKE_ANSWER_at_ssl(WOLFSSL* ssl)
{
    use_SNI_at_ssl(ssl);
    wolfSSL_SNI_SetOptions(ssl, WOLFSSL_SNI_HOST_NAME,
                                                WOLFSSL_SNI_ANSWER_ON_MISMATCH);
}

static void use_MANDATORY_SNI_at_ctx(WOLFSSL_CTX* ctx)
{
    use_SNI_at_ctx(ctx);
    wolfSSL_CTX_SNI_SetOptions(ctx, WOLFSSL_SNI_HOST_NAME,
                                                  WOLFSSL_SNI_ABORT_ON_ABSENCE);
}

static void use_MANDATORY_SNI_at_ssl(WOLFSSL* ssl)
{
    use_SNI_at_ssl(ssl);
    wolfSSL_SNI_SetOptions(ssl, WOLFSSL_SNI_HOST_NAME,
                                                  WOLFSSL_SNI_ABORT_ON_ABSENCE);
}

static void use_PSEUDO_MANDATORY_SNI_at_ctx(WOLFSSL_CTX* ctx)
{
    use_SNI_at_ctx(ctx);
    wolfSSL_CTX_SNI_SetOptions(ctx, WOLFSSL_SNI_HOST_NAME,
                 WOLFSSL_SNI_ANSWER_ON_MISMATCH | WOLFSSL_SNI_ABORT_ON_ABSENCE);
}

static void verify_UNKNOWN_SNI_on_server(WOLFSSL* ssl)
{
    AssertIntEQ(UNKNOWN_SNI_HOST_NAME_E, wolfSSL_get_error(ssl, 0));
}

static void verify_SNI_ABSENT_on_server(WOLFSSL* ssl)
{
    AssertIntEQ(SNI_ABSENT_ERROR, wolfSSL_get_error(ssl, 0));
}

static void verify_SNI_no_matching(WOLFSSL* ssl)
{
    byte type = WOLFSSL_SNI_HOST_NAME;
    char* request = (char*) &type; /* to be overwriten */

    AssertIntEQ(WOLFSSL_SNI_NO_MATCH, wolfSSL_SNI_Status(ssl, type));
    AssertNotNull(request);
    AssertIntEQ(0, wolfSSL_SNI_GetRequest(ssl, type, (void**) &request));
    AssertNull(request);
}

static void verify_SNI_real_matching(WOLFSSL* ssl)
{
    byte type = WOLFSSL_SNI_HOST_NAME;
    char* request = NULL;

    AssertIntEQ(WOLFSSL_SNI_REAL_MATCH, wolfSSL_SNI_Status(ssl, type));
    AssertIntEQ(15, wolfSSL_SNI_GetRequest(ssl, type, (void**) &request));
    AssertNotNull(request);
    AssertStrEQ("www.wolfssl.com", request);
}

static void verify_SNI_fake_matching(WOLFSSL* ssl)
{
    byte type = WOLFSSL_SNI_HOST_NAME;
    char* request = NULL;

    AssertIntEQ(WOLFSSL_SNI_FAKE_MATCH, wolfSSL_SNI_Status(ssl, type));
    AssertIntEQ(15, wolfSSL_SNI_GetRequest(ssl, type, (void**) &request));
    AssertNotNull(request);
    AssertStrEQ("ww2.wolfssl.com", request);
}

static void verify_FATAL_ERROR_on_client(WOLFSSL* ssl)
{
    AssertIntEQ(FATAL_ERROR, wolfSSL_get_error(ssl, 0));
}
/* END of connection tests callbacks */

static void test_wolfSSL_UseSNI_connection(void)
{
    unsigned long i;
    callback_functions callbacks[] = {
        /* success case at ctx */
        {0, use_SNI_at_ctx, 0, 0},
        {0, use_SNI_at_ctx, 0, verify_SNI_real_matching},

        /* success case at ssl */
        {0, 0, use_SNI_at_ssl, 0},
        {0, 0, use_SNI_at_ssl, verify_SNI_real_matching},

        /* default missmatch behavior */
        {0, 0, different_SNI_at_ssl, verify_FATAL_ERROR_on_client},
        {0, 0, use_SNI_at_ssl,       verify_UNKNOWN_SNI_on_server},

        /* continue on missmatch */
        {0, 0, different_SNI_at_ssl,         0},
        {0, 0, use_SNI_WITH_CONTINUE_at_ssl, verify_SNI_no_matching},

        /* fake answer on missmatch */
        {0, 0, different_SNI_at_ssl,            0},
        {0, 0, use_SNI_WITH_FAKE_ANSWER_at_ssl, verify_SNI_fake_matching},

        /* sni abort - success */
        {0, use_SNI_at_ctx,           0, 0},
        {0, use_MANDATORY_SNI_at_ctx, 0, verify_SNI_real_matching},

        /* sni abort - abort when absent (ctx) */
        {0, 0,                        0, verify_FATAL_ERROR_on_client},
        {0, use_MANDATORY_SNI_at_ctx, 0, verify_SNI_ABSENT_on_server},

        /* sni abort - abort when absent (ssl) */
        {0, 0, 0,                        verify_FATAL_ERROR_on_client},
        {0, 0, use_MANDATORY_SNI_at_ssl, verify_SNI_ABSENT_on_server},

        /* sni abort - success when overwriten */
        {0, 0, 0, 0},
        {0, use_MANDATORY_SNI_at_ctx, use_SNI_at_ssl, verify_SNI_no_matching},

        /* sni abort - success when allowing missmatches */
        {0, 0, different_SNI_at_ssl, 0},
        {0, use_PSEUDO_MANDATORY_SNI_at_ctx, 0, verify_SNI_fake_matching},
    };

    for (i = 0; i < sizeof(callbacks) / sizeof(callback_functions); i += 2) {
        callbacks[i    ].method = wolfSSLv23_client_method;
        callbacks[i + 1].method = wolfSSLv23_server_method;
        test_wolfSSL_client_server(&callbacks[i], &callbacks[i + 1]);
    }
}

static void test_wolfSSL_SNI_GetFromBuffer(void)
{
    byte buffer[] = { /* www.paypal.com */
        0x00, 0x00, 0x00, 0x00, 0xff, 0x01, 0x00, 0x00, 0x60, 0x03, 0x03, 0x5c,
        0xc4, 0xb3, 0x8c, 0x87, 0xef, 0xa4, 0x09, 0xe0, 0x02, 0xab, 0x86, 0xca,
        0x76, 0xf0, 0x9e, 0x01, 0x65, 0xf6, 0xa6, 0x06, 0x13, 0x1d, 0x0f, 0xa5,
        0x79, 0xb0, 0xd4, 0x77, 0x22, 0xeb, 0x1a, 0x00, 0x00, 0x16, 0x00, 0x6b,
        0x00, 0x67, 0x00, 0x39, 0x00, 0x33, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35,
        0x00, 0x2f, 0x00, 0x05, 0x00, 0x04, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x21,
        0x00, 0x00, 0x00, 0x13, 0x00, 0x11, 0x00, 0x00, 0x0e, 0x77, 0x77, 0x77,
        0x2e, 0x70, 0x61, 0x79, 0x70, 0x61, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x00,
        0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x01, 0x02, 0x01
    };

    byte buffer2[] = { /* api.textmate.org */
        0x16, 0x03, 0x01, 0x00, 0xc6, 0x01, 0x00, 0x00, 0xc2, 0x03, 0x03, 0x52,
        0x8b, 0x7b, 0xca, 0x69, 0xec, 0x97, 0xd5, 0x08, 0x03, 0x50, 0xfe, 0x3b,
        0x99, 0xc3, 0x20, 0xce, 0xa5, 0xf6, 0x99, 0xa5, 0x71, 0xf9, 0x57, 0x7f,
        0x04, 0x38, 0xf6, 0x11, 0x0b, 0xb8, 0xd3, 0x00, 0x00, 0x5e, 0x00, 0xff,
        0xc0, 0x24, 0xc0, 0x23, 0xc0, 0x0a, 0xc0, 0x09, 0xc0, 0x07, 0xc0, 0x08,
        0xc0, 0x28, 0xc0, 0x27, 0xc0, 0x14, 0xc0, 0x13, 0xc0, 0x11, 0xc0, 0x12,
        0xc0, 0x26, 0xc0, 0x25, 0xc0, 0x2a, 0xc0, 0x29, 0xc0, 0x05, 0xc0, 0x04,
        0xc0, 0x02, 0xc0, 0x03, 0xc0, 0x0f, 0xc0, 0x0e, 0xc0, 0x0c, 0xc0, 0x0d,
        0x00, 0x3d, 0x00, 0x3c, 0x00, 0x2f, 0x00, 0x05, 0x00, 0x04, 0x00, 0x35,
        0x00, 0x0a, 0x00, 0x67, 0x00, 0x6b, 0x00, 0x33, 0x00, 0x39, 0x00, 0x16,
        0x00, 0xaf, 0x00, 0xae, 0x00, 0x8d, 0x00, 0x8c, 0x00, 0x8a, 0x00, 0x8b,
        0x00, 0xb1, 0x00, 0xb0, 0x00, 0x2c, 0x00, 0x3b, 0x01, 0x00, 0x00, 0x3b,
        0x00, 0x00, 0x00, 0x15, 0x00, 0x13, 0x00, 0x00, 0x10, 0x61, 0x70, 0x69,
        0x2e, 0x74, 0x65, 0x78, 0x74, 0x6d, 0x61, 0x74, 0x65, 0x2e, 0x6f, 0x72,
        0x67, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00,
        0x19, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x0d, 0x00, 0x0c, 0x00,
        0x0a, 0x05, 0x01, 0x04, 0x01, 0x02, 0x01, 0x04, 0x03, 0x02, 0x03
    };

    byte buffer3[] = { /* no sni extension */
        0x16, 0x03, 0x03, 0x00, 0x4d, 0x01, 0x00, 0x00, 0x49, 0x03, 0x03, 0xea,
        0xa1, 0x9f, 0x60, 0xdd, 0x52, 0x12, 0x13, 0xbd, 0x84, 0x34, 0xd5, 0x1c,
        0x38, 0x25, 0xa8, 0x97, 0xd2, 0xd5, 0xc6, 0x45, 0xaf, 0x1b, 0x08, 0xe4,
        0x1e, 0xbb, 0xdf, 0x9d, 0x39, 0xf0, 0x65, 0x00, 0x00, 0x16, 0x00, 0x6b,
        0x00, 0x67, 0x00, 0x39, 0x00, 0x33, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35,
        0x00, 0x2f, 0x00, 0x05, 0x00, 0x04, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x0a,
        0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x01, 0x02, 0x01
    };

    byte buffer4[] = { /* last extension has zero size */
        0x16, 0x03, 0x01, 0x00, 0xba, 0x01, 0x00, 0x00,
        0xb6, 0x03, 0x03, 0x83, 0xa3, 0xe6, 0xdc, 0x16, 0xa1, 0x43, 0xe9, 0x45,
        0x15, 0xbd, 0x64, 0xa9, 0xb6, 0x07, 0xb4, 0x50, 0xc6, 0xdd, 0xff, 0xc2,
        0xd3, 0x0d, 0x4f, 0x36, 0xb4, 0x41, 0x51, 0x61, 0xc1, 0xa5, 0x9e, 0x00,
        0x00, 0x28, 0xcc, 0x14, 0xcc, 0x13, 0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x9e,
        0xc0, 0x0a, 0xc0, 0x09, 0xc0, 0x13, 0xc0, 0x14, 0xc0, 0x07, 0xc0, 0x11,
        0x00, 0x33, 0x00, 0x32, 0x00, 0x39, 0x00, 0x9c, 0x00, 0x2f, 0x00, 0x35,
        0x00, 0x0a, 0x00, 0x05, 0x00, 0x04, 0x01, 0x00, 0x00, 0x65, 0xff, 0x01,
        0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x17, 0x00,
        0x18, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x23, 0x00,
        0x00, 0x33, 0x74, 0x00, 0x00, 0x00, 0x10, 0x00, 0x1b, 0x00, 0x19, 0x06,
        0x73, 0x70, 0x64, 0x79, 0x2f, 0x33, 0x08, 0x73, 0x70, 0x64, 0x79, 0x2f,
        0x33, 0x2e, 0x31, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
        0x75, 0x50, 0x00, 0x00, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x0d, 0x00, 0x12, 0x00, 0x10, 0x04, 0x01, 0x05, 0x01, 0x02,
        0x01, 0x04, 0x03, 0x05, 0x03, 0x02, 0x03, 0x04, 0x02, 0x02, 0x02, 0x00,
        0x12, 0x00, 0x00
    };

    byte buffer5[] = { /* SSL v2.0 client hello */
        0x00, 0x2b, 0x01, 0x03, 0x01, 0x00, 0x09, 0x00, 0x00,
        /* dummy bytes bellow, just to pass size check */
        0xb6, 0x03, 0x03, 0x83, 0xa3, 0xe6, 0xdc, 0x16, 0xa1, 0x43, 0xe9, 0x45,
        0x15, 0xbd, 0x64, 0xa9, 0xb6, 0x07, 0xb4, 0x50, 0xc6, 0xdd, 0xff, 0xc2,
        0xd3, 0x0d, 0x4f, 0x36, 0xb4, 0x41, 0x51, 0x61, 0xc1, 0xa5, 0x9e, 0x00,
    };

    byte result[32] = {0};
    word32 length   = 32;

    AssertIntEQ(0, wolfSSL_SNI_GetFromBuffer(buffer4, sizeof(buffer4),
                                                           0, result, &length));

    AssertIntEQ(0, wolfSSL_SNI_GetFromBuffer(buffer3, sizeof(buffer3),
                                                           0, result, &length));

    AssertIntEQ(0, wolfSSL_SNI_GetFromBuffer(buffer2, sizeof(buffer2),
                                                           1, result, &length));

    AssertIntEQ(BUFFER_ERROR, wolfSSL_SNI_GetFromBuffer(buffer, sizeof(buffer),
                                                           0, result, &length));
    buffer[0] = 0x16;

    AssertIntEQ(BUFFER_ERROR, wolfSSL_SNI_GetFromBuffer(buffer, sizeof(buffer),
                                                           0, result, &length));
    buffer[1] = 0x03;

    AssertIntEQ(SNI_UNSUPPORTED, wolfSSL_SNI_GetFromBuffer(buffer,
                                           sizeof(buffer), 0, result, &length));
    buffer[2] = 0x03;

    AssertIntEQ(INCOMPLETE_DATA, wolfSSL_SNI_GetFromBuffer(buffer,
                                           sizeof(buffer), 0, result, &length));
    buffer[4] = 0x64;

    AssertIntEQ(SSL_SUCCESS, wolfSSL_SNI_GetFromBuffer(buffer, sizeof(buffer),
                                                           0, result, &length));
    result[length] = 0;
    AssertStrEQ("www.paypal.com", (const char*) result);

    length = 32;

    AssertIntEQ(SSL_SUCCESS, wolfSSL_SNI_GetFromBuffer(buffer2, sizeof(buffer2),
                                                           0, result, &length));
    result[length] = 0;
    AssertStrEQ("api.textmate.org", (const char*) result);

    /* SSL v2.0 tests */
    AssertIntEQ(SNI_UNSUPPORTED, wolfSSL_SNI_GetFromBuffer(buffer5,
                                          sizeof(buffer5), 0, result, &length));

    buffer5[2] = 0x02;
    AssertIntEQ(BUFFER_ERROR, wolfSSL_SNI_GetFromBuffer(buffer5,
                                          sizeof(buffer5), 0, result, &length));

    buffer5[2] = 0x01; buffer5[6] = 0x08;
    AssertIntEQ(BUFFER_ERROR, wolfSSL_SNI_GetFromBuffer(buffer5,
                                          sizeof(buffer5), 0, result, &length));

    buffer5[6] = 0x09; buffer5[8] = 0x01;
    AssertIntEQ(BUFFER_ERROR, wolfSSL_SNI_GetFromBuffer(buffer5,
                                          sizeof(buffer5), 0, result, &length));
}

#endif /* HAVE_SNI */

static void test_wolfSSL_UseSNI(void)
{
#ifdef HAVE_SNI
    test_wolfSSL_UseSNI_params();
    test_wolfSSL_UseSNI_connection();

    test_wolfSSL_SNI_GetFromBuffer();
#endif
}

static void test_wolfSSL_UseMaxFragment(void)
{
#ifdef HAVE_MAX_FRAGMENT
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    WOLFSSL     *ssl = wolfSSL_new(ctx);

    AssertNotNull(ctx);
    AssertNotNull(ssl);

    /* error cases */
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_UseMaxFragment(NULL, WOLFSSL_MFL_2_9));
    AssertIntNE(SSL_SUCCESS, wolfSSL_UseMaxFragment(    NULL, WOLFSSL_MFL_2_9));
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_UseMaxFragment(ctx, 0));
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_UseMaxFragment(ctx, 6));
    AssertIntNE(SSL_SUCCESS, wolfSSL_UseMaxFragment(ssl, 0));
    AssertIntNE(SSL_SUCCESS, wolfSSL_UseMaxFragment(ssl, 6));

    /* success case */
    AssertIntEQ(SSL_SUCCESS, wolfSSL_CTX_UseMaxFragment(ctx,  WOLFSSL_MFL_2_9));
    AssertIntEQ(SSL_SUCCESS, wolfSSL_CTX_UseMaxFragment(ctx,  WOLFSSL_MFL_2_10));
    AssertIntEQ(SSL_SUCCESS, wolfSSL_CTX_UseMaxFragment(ctx,  WOLFSSL_MFL_2_11));
    AssertIntEQ(SSL_SUCCESS, wolfSSL_CTX_UseMaxFragment(ctx,  WOLFSSL_MFL_2_12));
    AssertIntEQ(SSL_SUCCESS, wolfSSL_CTX_UseMaxFragment(ctx,  WOLFSSL_MFL_2_13));
    AssertIntEQ(SSL_SUCCESS, wolfSSL_UseMaxFragment(    ssl,  WOLFSSL_MFL_2_9));
    AssertIntEQ(SSL_SUCCESS, wolfSSL_UseMaxFragment(    ssl,  WOLFSSL_MFL_2_10));
    AssertIntEQ(SSL_SUCCESS, wolfSSL_UseMaxFragment(    ssl,  WOLFSSL_MFL_2_11));
    AssertIntEQ(SSL_SUCCESS, wolfSSL_UseMaxFragment(    ssl,  WOLFSSL_MFL_2_12));
    AssertIntEQ(SSL_SUCCESS, wolfSSL_UseMaxFragment(    ssl,  WOLFSSL_MFL_2_13));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
}

static void test_wolfSSL_UseTruncatedHMAC(void)
{
#ifdef HAVE_TRUNCATED_HMAC
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    WOLFSSL     *ssl = wolfSSL_new(ctx);

    AssertNotNull(ctx);
    AssertNotNull(ssl);

    /* error cases */
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_UseTruncatedHMAC(NULL));
    AssertIntNE(SSL_SUCCESS, wolfSSL_UseTruncatedHMAC(NULL));

    /* success case */
    AssertIntEQ(SSL_SUCCESS, wolfSSL_CTX_UseTruncatedHMAC(ctx));
    AssertIntEQ(SSL_SUCCESS, wolfSSL_UseTruncatedHMAC(ssl));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
}

static void test_wolfSSL_UseSupportedCurve(void)
{
#ifdef HAVE_SUPPORTED_CURVES
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    WOLFSSL     *ssl = wolfSSL_new(ctx);

    AssertNotNull(ctx);
    AssertNotNull(ssl);

#ifndef NO_WOLFSSL_CLIENT
    /* error cases */
    AssertIntNE(SSL_SUCCESS,
                      wolfSSL_CTX_UseSupportedCurve(NULL, WOLFSSL_ECC_SECP256R1));
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_UseSupportedCurve(ctx,  0));

    AssertIntNE(SSL_SUCCESS,
                          wolfSSL_UseSupportedCurve(NULL, WOLFSSL_ECC_SECP256R1));
    AssertIntNE(SSL_SUCCESS, wolfSSL_UseSupportedCurve(ssl,  0));

    /* success case */
    AssertIntEQ(SSL_SUCCESS,
                       wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_ECC_SECP256R1));
    AssertIntEQ(SSL_SUCCESS,
                           wolfSSL_UseSupportedCurve(ssl, WOLFSSL_ECC_SECP256R1));
#endif

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
}

#ifdef HAVE_ALPN

static void verify_ALPN_FATAL_ERROR_on_client(WOLFSSL* ssl)
{
    AssertIntEQ(UNKNOWN_ALPN_PROTOCOL_NAME_E, wolfSSL_get_error(ssl, 0));
}

static void use_ALPN_all(WOLFSSL* ssl)
{
    /* http/1.1,spdy/1,spdy/2,spdy/3 */
    char alpn_list[] = {0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x2c,
                        0x73, 0x70, 0x64, 0x79, 0x2f, 0x31, 0x2c,
                        0x73, 0x70, 0x64, 0x79, 0x2f, 0x32, 0x2c,
                        0x73, 0x70, 0x64, 0x79, 0x2f, 0x33};
    AssertIntEQ(SSL_SUCCESS, wolfSSL_UseALPN(ssl, alpn_list, sizeof(alpn_list),
                                             WOLFSSL_ALPN_FAILED_ON_MISMATCH));
}

static void use_ALPN_all_continue(WOLFSSL* ssl)
{
    /* http/1.1,spdy/1,spdy/2,spdy/3 */
    char alpn_list[] = {0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x2c,
        0x73, 0x70, 0x64, 0x79, 0x2f, 0x31, 0x2c,
        0x73, 0x70, 0x64, 0x79, 0x2f, 0x32, 0x2c,
        0x73, 0x70, 0x64, 0x79, 0x2f, 0x33};
    AssertIntEQ(SSL_SUCCESS, wolfSSL_UseALPN(ssl, alpn_list, sizeof(alpn_list),
                                             WOLFSSL_ALPN_CONTINUE_ON_MISMATCH));
}

static void use_ALPN_one(WOLFSSL* ssl)
{
    /* spdy/2 */
    char proto[] = {0x73, 0x70, 0x64, 0x79, 0x2f, 0x32};

    AssertIntEQ(SSL_SUCCESS, wolfSSL_UseALPN(ssl, proto, sizeof(proto),
                                             WOLFSSL_ALPN_FAILED_ON_MISMATCH));
}

static void use_ALPN_unknown(WOLFSSL* ssl)
{
    /* http/2.0 */
    char proto[] = {0x68, 0x74, 0x74, 0x70, 0x2f, 0x32, 0x2e, 0x30};

    AssertIntEQ(SSL_SUCCESS, wolfSSL_UseALPN(ssl, proto, sizeof(proto),
                                             WOLFSSL_ALPN_FAILED_ON_MISMATCH));
}

static void use_ALPN_unknown_continue(WOLFSSL* ssl)
{
    /* http/2.0 */
    char proto[] = {0x68, 0x74, 0x74, 0x70, 0x2f, 0x32, 0x2e, 0x30};

    AssertIntEQ(SSL_SUCCESS, wolfSSL_UseALPN(ssl, proto, sizeof(proto),
                                             WOLFSSL_ALPN_CONTINUE_ON_MISMATCH));
}

static void verify_ALPN_not_matching_spdy3(WOLFSSL* ssl)
{
    /* spdy/3 */
    char nego_proto[] = {0x73, 0x70, 0x64, 0x79, 0x2f, 0x33};

    char *proto;
    word16 protoSz = 0;

    AssertIntEQ(SSL_SUCCESS, wolfSSL_ALPN_GetProtocol(ssl, &proto, &protoSz));

    /* check value */
    AssertIntNE(1, sizeof(nego_proto) == protoSz);
    AssertIntNE(0, XMEMCMP(nego_proto, proto, sizeof(nego_proto)));
}

static void verify_ALPN_not_matching_continue(WOLFSSL* ssl)
{
    char *proto = NULL;
    word16 protoSz = 0;

    AssertIntEQ(SSL_ALPN_NOT_FOUND,
                wolfSSL_ALPN_GetProtocol(ssl, &proto, &protoSz));

    /* check value */
    AssertIntEQ(1, (0 == protoSz));
    AssertIntEQ(1, (NULL == proto));
}

static void verify_ALPN_matching_http1(WOLFSSL* ssl)
{
    /* http/1.1 */
    char nego_proto[] = {0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31};
    char *proto;
    word16 protoSz = 0;

    AssertIntEQ(SSL_SUCCESS, wolfSSL_ALPN_GetProtocol(ssl, &proto, &protoSz));

    /* check value */
    AssertIntEQ(1, sizeof(nego_proto) == protoSz);
    AssertIntEQ(0, XMEMCMP(nego_proto, proto, protoSz));
}

static void verify_ALPN_matching_spdy2(WOLFSSL* ssl)
{
    /* spdy/2 */
    char nego_proto[] = {0x73, 0x70, 0x64, 0x79, 0x2f, 0x32};
    char *proto;
    word16 protoSz = 0;

    AssertIntEQ(SSL_SUCCESS, wolfSSL_ALPN_GetProtocol(ssl, &proto, &protoSz));

    /* check value */
    AssertIntEQ(1, sizeof(nego_proto) == protoSz);
    AssertIntEQ(0, XMEMCMP(nego_proto, proto, protoSz));
}

static void verify_ALPN_client_list(WOLFSSL* ssl)
{
    /* http/1.1,spdy/1,spdy/2,spdy/3 */
    char alpn_list[] = {0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x2c,
                        0x73, 0x70, 0x64, 0x79, 0x2f, 0x31, 0x2c,
                        0x73, 0x70, 0x64, 0x79, 0x2f, 0x32, 0x2c,
                        0x73, 0x70, 0x64, 0x79, 0x2f, 0x33};
    char    *clist = NULL;
    word16  clistSz = 0;

    AssertIntEQ(SSL_SUCCESS, wolfSSL_ALPN_GetPeerProtocol(ssl, &clist,
                                                          &clistSz));

    /* check value */
    AssertIntEQ(1, sizeof(alpn_list) == clistSz);
    AssertIntEQ(0, XMEMCMP(alpn_list, clist, clistSz));

    AssertIntEQ(SSL_SUCCESS, wolfSSL_ALPN_FreePeerProtocol(ssl, &clist));
}

static void test_wolfSSL_UseALPN_connection(void)
{
    unsigned long i;
    callback_functions callbacks[] = {
        /* success case same list */
        {0, 0, use_ALPN_all, 0},
        {0, 0, use_ALPN_all, verify_ALPN_matching_http1},

        /* success case only one for server */
        {0, 0, use_ALPN_all, 0},
        {0, 0, use_ALPN_one, verify_ALPN_matching_spdy2},

        /* success case only one for client */
        {0, 0, use_ALPN_one, 0},
        {0, 0, use_ALPN_all, verify_ALPN_matching_spdy2},

        /* success case none for client */
        {0, 0, 0, 0},
        {0, 0, use_ALPN_all, 0},

        /* success case missmatch behavior but option 'continue' set */
        {0, 0, use_ALPN_all_continue, verify_ALPN_not_matching_continue},
        {0, 0, use_ALPN_unknown_continue, 0},

        /* success case read protocol send by client */
        {0, 0, use_ALPN_all, 0},
        {0, 0, use_ALPN_one, verify_ALPN_client_list},

        /* missmatch behavior with same list
         * the first and only this one must be taken */
        {0, 0, use_ALPN_all, 0},
        {0, 0, use_ALPN_all, verify_ALPN_not_matching_spdy3},

        /* default missmatch behavior */
        {0, 0, use_ALPN_all, 0},
        {0, 0, use_ALPN_unknown, verify_ALPN_FATAL_ERROR_on_client},
    };

    for (i = 0; i < sizeof(callbacks) / sizeof(callback_functions); i += 2) {
        callbacks[i    ].method = wolfSSLv23_client_method;
        callbacks[i + 1].method = wolfSSLv23_server_method;
        test_wolfSSL_client_server(&callbacks[i], &callbacks[i + 1]);
    }
}

static void test_wolfSSL_UseALPN_params(void)
{
    /* "http/1.1" */
    char http1[] = {0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31};
    /* "spdy/1" */
    char spdy1[] = {0x73, 0x70, 0x64, 0x79, 0x2f, 0x31};
    /* "spdy/2" */
    char spdy2[] = {0x73, 0x70, 0x64, 0x79, 0x2f, 0x32};
    /* "spdy/3" */
    char spdy3[] = {0x73, 0x70, 0x64, 0x79, 0x2f, 0x33};
    char buff[256];
    word32 idx;

    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    WOLFSSL     *ssl = wolfSSL_new(ctx);

    AssertNotNull(ctx);
    AssertNotNull(ssl);

    /* error cases */
    AssertIntNE(SSL_SUCCESS,
                wolfSSL_UseALPN(NULL, http1, sizeof(http1),
                                WOLFSSL_ALPN_FAILED_ON_MISMATCH));
    AssertIntNE(SSL_SUCCESS, wolfSSL_UseALPN(ssl, NULL, 0,
                                             WOLFSSL_ALPN_FAILED_ON_MISMATCH));

    /* success case */
    /* http1 only */
    AssertIntEQ(SSL_SUCCESS,
                wolfSSL_UseALPN(ssl, http1, sizeof(http1),
                                WOLFSSL_ALPN_FAILED_ON_MISMATCH));

    /* http1, spdy1 */
    XMEMCPY(buff, http1, sizeof(http1));
    idx = sizeof(http1);
    buff[idx++] = ',';
    XMEMCPY(buff+idx, spdy1, sizeof(spdy1));
    idx += sizeof(spdy1);
    AssertIntEQ(SSL_SUCCESS, wolfSSL_UseALPN(ssl, buff, idx,
                                             WOLFSSL_ALPN_FAILED_ON_MISMATCH));

    /* http1, spdy2, spdy1 */
    XMEMCPY(buff, http1, sizeof(http1));
    idx = sizeof(http1);
    buff[idx++] = ',';
    XMEMCPY(buff+idx, spdy2, sizeof(spdy2));
    idx += sizeof(spdy2);
    buff[idx++] = ',';
    XMEMCPY(buff+idx, spdy1, sizeof(spdy1));
    idx += sizeof(spdy1);
    AssertIntEQ(SSL_SUCCESS, wolfSSL_UseALPN(ssl, buff, idx,
                                             WOLFSSL_ALPN_FAILED_ON_MISMATCH));

    /* spdy3, http1, spdy2, spdy1 */
    XMEMCPY(buff, spdy3, sizeof(spdy3));
    idx = sizeof(spdy3);
    buff[idx++] = ',';
    XMEMCPY(buff+idx, http1, sizeof(http1));
    idx += sizeof(http1);
    buff[idx++] = ',';
    XMEMCPY(buff+idx, spdy2, sizeof(spdy2));
    idx += sizeof(spdy2);
    buff[idx++] = ',';
    XMEMCPY(buff+idx, spdy1, sizeof(spdy1));
    idx += sizeof(spdy1);
    AssertIntEQ(SSL_SUCCESS, wolfSSL_UseALPN(ssl, buff, idx,
                                             WOLFSSL_ALPN_CONTINUE_ON_MISMATCH));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
}
#endif /* HAVE_ALPN  */

static void test_wolfSSL_UseALPN(void)
{
#ifdef HAVE_ALPN
    test_wolfSSL_UseALPN_connection();
    test_wolfSSL_UseALPN_params();
#endif
}

static void test_wolfSSL_DisableExtendedMasterSecret(void)
{
#ifdef HAVE_EXTENDED_MASTER
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    WOLFSSL     *ssl = wolfSSL_new(ctx);

    AssertNotNull(ctx);
    AssertNotNull(ssl);

    /* error cases */
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_DisableExtendedMasterSecret(NULL));
    AssertIntNE(SSL_SUCCESS, wolfSSL_DisableExtendedMasterSecret(NULL));

    /* success cases */
    AssertIntEQ(SSL_SUCCESS, wolfSSL_CTX_DisableExtendedMasterSecret(ctx));
    AssertIntEQ(SSL_SUCCESS, wolfSSL_DisableExtendedMasterSecret(ssl));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
}

/*----------------------------------------------------------------------------*
 | X509 Tests
 *----------------------------------------------------------------------------*/
static void test_wolfSSL_X509_NAME_get_entry(void)
{
#if !defined(NO_CERTS) && !defined(NO_RSA)
#if defined(OPENSSL_EXTRA) && (defined(KEEP_PEER_CERT) || defined(SESSION_CERTS)) \
    && (defined(HAVE_LIGHTY) || defined(WOLFSSL_MYSQL_COMPATIBLE))
    printf(testingFmt, "wolfSSL_X509_NAME_get_entry()");

    {
        /* use openssl like name to test mapping */
        X509_NAME_ENTRY* ne = NULL;
        X509_NAME* name = NULL;
        char* subCN = NULL;
        X509* x509;
        ASN1_STRING* asn;
        int idx;

    #ifndef NO_FILESYSTEM
        x509 = wolfSSL_X509_load_certificate_file(cliCert, SSL_FILETYPE_PEM);
        AssertNotNull(x509);

        name = X509_get_subject_name(x509);

        idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
        AssertIntGE(idx, 0);

        ne = X509_NAME_get_entry(name, idx);
        AssertNotNull(ne);

        asn = X509_NAME_ENTRY_get_data(ne);
        AssertNotNull(asn);

        subCN = (char*)ASN1_STRING_data(asn);
        AssertNotNull(subCN);

        wolfSSL_FreeX509(x509);
    #endif

    }

    printf(resultFmt, passed);
#endif /* OPENSSL_EXTRA */
#endif /* !NO_CERTS */
}


/* Testing functions dealing with PKCS12 parsing out X509 certs */
static void test_wolfSSL_PKCS12(void)
{
    /* .p12 file is encrypted with DES3 */
#if defined(OPENSSL_EXTRA) && !defined(NO_DES3) && !defined(NO_FILESYSTEM) && \
    !defined(NO_ASN) && !defined(NO_PWDBASED) && !defined(NO_RSA)
    byte buffer[5300];
    char file[] = "./certs/test-servercert.p12";
    char pass[] = "a password";
    FILE *f;
    int  bytes, ret;
    WOLFSSL_BIO      *bio;
    WOLFSSL_EVP_PKEY *pkey;
    WC_PKCS12        *pkcs12;
    WC_PKCS12        *pkcs12_2;
    WOLFSSL_X509     *cert;
    WOLFSSL_X509     *tmp;
    STACK_OF(WOLFSSL_X509) *ca;

    printf(testingFmt, "wolfSSL_PKCS12()");

    f = fopen(file, "rb");
    AssertNotNull(f);
    bytes = (int)fread(buffer, 1, sizeof(buffer), f);
    fclose(f);

    bio = BIO_new_mem_buf((void*)buffer, bytes);
    AssertNotNull(bio);

    pkcs12 = d2i_PKCS12_bio(bio, NULL);
    AssertNotNull(pkcs12);
    PKCS12_free(pkcs12);

    d2i_PKCS12_bio(bio, &pkcs12);
    AssertNotNull(pkcs12);

    /* check verify MAC fail case */
    ret = PKCS12_parse(pkcs12, "bad", &pkey, &cert, NULL);
    AssertIntEQ(ret, 0);
    AssertNull(pkey);
    AssertNull(cert);

    /* check parse with no extra certs kept */
    ret = PKCS12_parse(pkcs12, "wolfSSL test", &pkey, &cert, NULL);
    AssertIntEQ(ret, 1);
    AssertNotNull(pkey);
    AssertNotNull(cert);

    wolfSSL_EVP_PKEY_free(pkey);
    wolfSSL_X509_free(cert);

    /* check parse with extra certs kept */
    ret = PKCS12_parse(pkcs12, "wolfSSL test", &pkey, &cert, &ca);
    AssertIntEQ(ret, 1);
    AssertNotNull(pkey);
    AssertNotNull(cert);
    AssertNotNull(ca);


    /* should be 2 other certs on stack */
    tmp = sk_X509_pop(ca);
    AssertNotNull(tmp);
    X509_free(tmp);
    tmp = sk_X509_pop(ca);
    AssertNotNull(tmp);
    X509_free(tmp);
    AssertNull(sk_X509_pop(ca));

    EVP_PKEY_free(pkey);
    X509_free(cert);
    sk_X509_pop_free(ca, X509_free);

    /* check PKCS12_create */
    AssertNull(PKCS12_create(pass, NULL, NULL, NULL, NULL, -1, -1, -1, -1,0));
    AssertIntEQ(PKCS12_parse(pkcs12, "wolfSSL test", &pkey, &cert, &ca),
            SSL_SUCCESS);
    AssertNotNull((pkcs12_2 = PKCS12_create(pass, NULL, pkey, cert, ca,
                    -1, -1, 100, -1, 0)));
    EVP_PKEY_free(pkey);
    X509_free(cert);
    sk_X509_free(ca);

    AssertIntEQ(PKCS12_parse(pkcs12_2, "a password", &pkey, &cert, &ca),
            SSL_SUCCESS);
    PKCS12_free(pkcs12_2);
    AssertNotNull((pkcs12_2 = PKCS12_create(pass, NULL, pkey, cert, ca,
             NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
             NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
             2000, 1, 0)));
    EVP_PKEY_free(pkey);
    X509_free(cert);
    sk_X509_free(ca);

    AssertIntEQ(PKCS12_parse(pkcs12_2, "a password", &pkey, &cert, &ca),
            SSL_SUCCESS);

    /* should be 2 other certs on stack */
    tmp = sk_X509_pop(ca);
    AssertNotNull(tmp);
    X509_free(tmp);
    tmp = sk_X509_pop(ca);
    AssertNotNull(tmp);
    X509_free(tmp);
    AssertNull(sk_X509_pop(ca));


#ifndef NO_RC4
    PKCS12_free(pkcs12_2);
    AssertNotNull((pkcs12_2 = PKCS12_create(pass, NULL, pkey, cert, NULL,
             NID_pbe_WithSHA1And128BitRC4,
             NID_pbe_WithSHA1And128BitRC4,
             2000, 1, 0)));
    EVP_PKEY_free(pkey);
    X509_free(cert);
    sk_X509_free(ca);

    AssertIntEQ(PKCS12_parse(pkcs12_2, "a password", &pkey, &cert, &ca),
            SSL_SUCCESS);

#endif /* NO_RC4 */

    EVP_PKEY_free(pkey);
    X509_free(cert);
    BIO_free(bio);
    PKCS12_free(pkcs12);
    PKCS12_free(pkcs12_2);
    sk_X509_free(ca);

    printf(resultFmt, passed);
#endif /* OPENSSL_EXTRA */
}


/* Testing function  wolfSSL_CTX_SetMinVersion; sets the minimum downgrade
 * version allowed.
 * POST: 1 on success.
 */
static int test_wolfSSL_CTX_SetMinVersion(void)
{
    WOLFSSL_CTX*            ctx;
    int                     failFlag, itr;

    #ifndef NO_OLD_TLS
        const int versions[]  = { WOLFSSL_TLSV1, WOLFSSL_TLSV1_1,
                                  WOLFSSL_TLSV1_2 };
    #else
        const int versions[]  = { WOLFSSL_TLSV1_2 };
    #endif

    failFlag = SSL_SUCCESS;

    AssertTrue(wolfSSL_Init());
    ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());

    printf(testingFmt, "wolfSSL_CTX_SetMinVersion()");

    for (itr = 0; itr < (int)(sizeof(versions)/sizeof(int)); itr++){
        if(wolfSSL_CTX_SetMinVersion(ctx, *(versions + itr)) != SSL_SUCCESS){
            failFlag = SSL_FAILURE;
        }
    }

    printf(resultFmt, failFlag == SSL_SUCCESS ? passed : failed);

    wolfSSL_CTX_free(ctx);
    AssertTrue(wolfSSL_Cleanup());

    return failFlag;

} /* END test_wolfSSL_CTX_SetMinVersion */


/*----------------------------------------------------------------------------*
 | OCSP Stapling
 *----------------------------------------------------------------------------*/


/* Testing wolfSSL_UseOCSPStapling function. OCSP stapling eliminates the need
 * need to contact the CA, lowering the cost of cert revocation checking.
 * PRE: HAVE_OCSP and HAVE_CERTIFICATE_STATUS_REQUEST
 * POST: 1 returned for success.
 */
static int test_wolfSSL_UseOCSPStapling(void)
{
    #if defined(HAVE_CERTIFICATE_STATUS_REQUEST) && defined(HAVE_OCSP)
        int             ret;
        WOLFSSL_CTX*    ctx;
        WOLFSSL*        ssl;

        wolfSSL_Init();
        ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
        ssl = wolfSSL_new(ctx);
        printf(testingFmt, "wolfSSL_UseOCSPStapling()");

        ret = wolfSSL_UseOCSPStapling(ssl, WOLFSSL_CSR2_OCSP,
                                    WOLFSSL_CSR2_OCSP_USE_NONCE);

        printf(resultFmt, ret == SSL_SUCCESS ? passed : failed);


        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);

        if(ret != SSL_SUCCESS){
            wolfSSL_Cleanup();
            return SSL_FAILURE;
        }

        return wolfSSL_Cleanup();
    #else
        return SSL_SUCCESS;
    #endif

} /*END test_wolfSSL_UseOCSPStapling */


/* Testing OCSP stapling version 2, wolfSSL_UseOCSPStaplingV2 funciton. OCSP
 * stapling eliminates the need ot contact the CA and lowers cert revocation
 * check.
 * PRE: HAVE_CERTIFICATE_STATUS_REQUEST_V2 and HAVE_OCSP defined.
 */
static int test_wolfSSL_UseOCSPStaplingV2(void)
{
    #if defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2) && defined(HAVE_OCSP)
        int                 ret;
        WOLFSSL_CTX*        ctx;
        WOLFSSL*            ssl;

        wolfSSL_Init();
        ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
        ssl = wolfSSL_new(ctx);
        printf(testingFmt, "wolfSSL_UseOCSPStaplingV2()");

        ret = wolfSSL_UseOCSPStaplingV2(ssl, WOLFSSL_CSR2_OCSP,
                                        WOLFSSL_CSR2_OCSP_USE_NONCE );

        printf(resultFmt, ret == SSL_SUCCESS ? passed : failed);

        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);

        if(ret != SSL_SUCCESS){
            wolfSSL_Cleanup();
            return SSL_FAILURE;
        }

        return wolfSSL_Cleanup();
    #else
        return SSL_SUCCESS;
    #endif

} /*END test_wolfSSL_UseOCSPStaplingV2*/


/*----------------------------------------------------------------------------*
 | Compatibility Tests
 *----------------------------------------------------------------------------*/


static void test_wolfSSL_X509_NAME(void)
{
    #if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && !defined(NO_FILESYSTEM) \
        && !defined(NO_RSA) && defined(WOLFSSL_CERT_GEN)
    X509* x509;
    const unsigned char* c;
    unsigned char buf[4096];
    int bytes;
    FILE* f;
    const X509_NAME* a;
    const X509_NAME* b;
    int sz;
    unsigned char* tmp;
    char file[] = "./certs/ca-cert.der";

    printf(testingFmt, "wolfSSL_X509_NAME()");

    /* test compile of depricated function, returns 0 */
    AssertIntEQ(CRYPTO_thread_id(), 0);

    AssertNotNull(a = X509_NAME_new());
    X509_NAME_free((X509_NAME*)a);

    f = fopen(file, "rb");
    AssertNotNull(f);
    bytes = (int)fread(buf, 1, sizeof(buf), f);
    fclose(f);

    c = buf;
    AssertNotNull(x509 = wolfSSL_X509_load_certificate_buffer(c, bytes,
                SSL_FILETYPE_ASN1));

    /* test cmp function */
    AssertNotNull(a = X509_get_issuer_name(x509));
    AssertNotNull(b = X509_get_subject_name(x509));

    AssertIntEQ(X509_NAME_cmp(a, b), 0); /* self signed should be 0 */

    tmp = buf;
    AssertIntGT((sz = i2d_X509_NAME((X509_NAME*)a, &tmp)), 0);
    if (tmp == buf) {
        printf("\nERROR - %s line %d failed with:", __FILE__, __LINE__);           \
        printf(" Expected pointer to be incremented\n");
        abort();
    }

    /* retry but with the function creating a buffer */
    tmp = NULL;
    AssertIntGT((sz = i2d_X509_NAME((X509_NAME*)b, &tmp)), 0);
    XFREE(tmp, NULL, DYNAMIC_TYPE_OPENSSL);

    X509_free(x509);

    printf(resultFmt, passed);
    #endif /* defined(OPENSSL_EXTRA) && !defined(NO_DES3) */
}


static void test_wolfSSL_DES(void)
{
    #if defined(OPENSSL_EXTRA) && !defined(NO_DES3)
    const_DES_cblock myDes;
    DES_cblock iv;
    DES_key_schedule key;
    word32 i;
    DES_LONG dl;
    unsigned char msg[] = "hello wolfssl";

    printf(testingFmt, "wolfSSL_DES()");

    DES_check_key(1);
    DES_set_key(&myDes, &key);

    /* check, check of odd parity */
    XMEMSET(myDes, 4, sizeof(const_DES_cblock));  myDes[0] = 3; /*set even parity*/
    XMEMSET(key, 5, sizeof(DES_key_schedule));
    AssertIntEQ(DES_set_key_checked(&myDes, &key), -1);
    AssertIntNE(key[0], myDes[0]); /* should not have copied over key */

    /* set odd parity for success case */
    DES_set_odd_parity(&myDes);
    AssertIntEQ(DES_set_key_checked(&myDes, &key), 0);
    for (i = 0; i < sizeof(DES_key_schedule); i++) {
        AssertIntEQ(key[i], myDes[i]);
    }
    AssertIntEQ(DES_is_weak_key(&myDes), 0);

    /* check weak key */
    XMEMSET(myDes, 1, sizeof(const_DES_cblock));
    XMEMSET(key, 5, sizeof(DES_key_schedule));
    AssertIntEQ(DES_set_key_checked(&myDes, &key), -2);
    AssertIntNE(key[0], myDes[0]); /* should not have copied over key */

    /* now do unchecked copy of a weak key over */
    DES_set_key_unchecked(&myDes, &key);
    /* compare arrays, should be the same */
    for (i = 0; i < sizeof(DES_key_schedule); i++) {
        AssertIntEQ(key[i], myDes[i]);
    }
    AssertIntEQ(DES_is_weak_key(&myDes), 1);

    /* check DES_key_sched API */
    XMEMSET(myDes, 1, sizeof(const_DES_cblock));
    AssertIntEQ(DES_key_sched(&myDes, NULL), 0);
    AssertIntEQ(DES_key_sched(NULL, &key),   0);
    AssertIntEQ(DES_key_sched(&myDes, &key), 0);
    /* compare arrays, should be the same */
    for (i = 0; i < sizeof(DES_key_schedule); i++) {
        AssertIntEQ(key[i], myDes[i]);
    }

    /* DES_cbc_cksum should return the last 4 of the last 8 bytes after
     * DES_cbc_encrypt on the input */
    XMEMSET(iv, 0, sizeof(DES_cblock));
    XMEMSET(myDes, 5, sizeof(const_DES_cblock));
    AssertIntGT((dl = DES_cbc_cksum(msg, &key, sizeof(msg), &myDes, &iv)), 0);
    AssertIntEQ(dl, 480052723);

    printf(resultFmt, passed);
    #endif /* defined(OPENSSL_EXTRA) && !defined(NO_DES3) */
}


static void test_wolfSSL_certs(void)
{
    #if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
       !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    X509*  x509;
    WOLFSSL*     ssl;
    WOLFSSL_CTX* ctx;
    STACK_OF(ASN1_OBJECT)* sk;
    int crit;

    printf(testingFmt, "wolfSSL_certs()");

    AssertNotNull(ctx = SSL_CTX_new(wolfSSLv23_server_method()));
    AssertTrue(SSL_CTX_use_certificate_file(ctx, svrCert, SSL_FILETYPE_PEM));
    AssertTrue(SSL_CTX_use_PrivateKey_file(ctx, svrKey, SSL_FILETYPE_PEM));
    #ifndef HAVE_USER_RSA
    AssertTrue(SSL_CTX_use_PrivateKey_file(ctx, cliKey, SSL_FILETYPE_PEM));
    AssertIntEQ(SSL_CTX_check_private_key(ctx), SSL_FAILURE);
    AssertTrue(SSL_CTX_use_PrivateKey_file(ctx, svrKey, SSL_FILETYPE_PEM));
    AssertIntEQ(SSL_CTX_check_private_key(ctx), SSL_SUCCESS);
    #endif
    AssertNotNull(ssl = SSL_new(ctx));

    AssertIntEQ(wolfSSL_check_private_key(ssl), SSL_SUCCESS);

    #ifdef HAVE_PK_CALLBACKS
    AssertIntEQ((int)SSL_set_tlsext_debug_arg(ssl, NULL), SSL_SUCCESS);
    #endif /* HAVE_PK_CALLBACKS */

    /* create and use x509 */
    x509 = wolfSSL_X509_load_certificate_file(cliCert, SSL_FILETYPE_PEM);
    AssertNotNull(x509);
    AssertIntEQ(SSL_use_certificate(ssl, x509), SSL_SUCCESS);

    #ifndef HAVE_USER_RSA
    /* with loading in a new cert the check on private key should now fail */
    AssertIntNE(wolfSSL_check_private_key(ssl), SSL_SUCCESS);
    #endif


    #if defined(USE_CERT_BUFFERS_2048)
        AssertIntEQ(SSL_use_certificate_ASN1(ssl,
                                  (unsigned char*)server_cert_der_2048,
                                  sizeof_server_cert_der_2048), SSL_SUCCESS);
    #endif

    #if !defined(NO_SHA) && !defined(NO_SHA256)
    /************* Get Digest of Certificate ******************/
    {
        byte   digest[64]; /* max digest size */
        word32 digestSz;

        XMEMSET(digest, 0, sizeof(digest));
        AssertIntEQ(X509_digest(x509, wolfSSL_EVP_sha1(), digest, &digestSz),
                    SSL_SUCCESS);
        AssertIntEQ(X509_digest(x509, wolfSSL_EVP_sha256(), digest, &digestSz),
                    SSL_SUCCESS);

        AssertIntEQ(X509_digest(NULL, wolfSSL_EVP_sha1(), digest, &digestSz),
                    SSL_FAILURE);
    }
    #endif /* !NO_SHA && !NO_SHA256*/

    /* test and checkout X509 extensions */
    sk = (STACK_OF(ASN1_OBJECT)*)X509_get_ext_d2i(x509, NID_basic_constraints,
            &crit, NULL);
    AssertNotNull(sk);
    AssertIntEQ(crit, 0);
    wolfSSL_sk_ASN1_OBJECT_free(sk);

    sk = (STACK_OF(ASN1_OBJECT)*)X509_get_ext_d2i(x509, NID_key_usage,
            &crit, NULL);
    /* AssertNotNull(sk); NID not yet supported */
    AssertIntEQ(crit, -1);
    wolfSSL_sk_ASN1_OBJECT_free(sk);

    sk = (STACK_OF(ASN1_OBJECT)*)X509_get_ext_d2i(x509, NID_ext_key_usage,
            &crit, NULL);
    /* AssertNotNull(sk); no extension set */
    wolfSSL_sk_ASN1_OBJECT_free(sk);

    sk = (STACK_OF(ASN1_OBJECT)*)X509_get_ext_d2i(x509,
            NID_authority_key_identifier, &crit, NULL);
    AssertNotNull(sk);
    wolfSSL_sk_ASN1_OBJECT_free(sk);

    sk = (STACK_OF(ASN1_OBJECT)*)X509_get_ext_d2i(x509,
            NID_private_key_usage_period, &crit, NULL);
    /* AssertNotNull(sk); NID not yet supported */
    AssertIntEQ(crit, -1);
    wolfSSL_sk_ASN1_OBJECT_free(sk);

    sk = (STACK_OF(ASN1_OBJECT)*)X509_get_ext_d2i(x509, NID_subject_alt_name,
            &crit, NULL);
    /* AssertNotNull(sk); no alt names set */
    wolfSSL_sk_ASN1_OBJECT_free(sk);

    sk = (STACK_OF(ASN1_OBJECT)*)X509_get_ext_d2i(x509, NID_issuer_alt_name,
            &crit, NULL);
    /* AssertNotNull(sk); NID not yet supported */
    AssertIntEQ(crit, -1);
    wolfSSL_sk_ASN1_OBJECT_free(sk);

    sk = (STACK_OF(ASN1_OBJECT)*)X509_get_ext_d2i(x509, NID_info_access, &crit,
            NULL);
    /* AssertNotNull(sk); no auth info set */
    wolfSSL_sk_ASN1_OBJECT_free(sk);

    sk = (STACK_OF(ASN1_OBJECT)*)X509_get_ext_d2i(x509, NID_sinfo_access,
            &crit, NULL);
    /* AssertNotNull(sk); NID not yet supported */
    AssertIntEQ(crit, -1);
    wolfSSL_sk_ASN1_OBJECT_free(sk);

    sk = (STACK_OF(ASN1_OBJECT)*)X509_get_ext_d2i(x509, NID_name_constraints,
            &crit, NULL);
    /* AssertNotNull(sk); NID not yet supported */
    AssertIntEQ(crit, -1);
    wolfSSL_sk_ASN1_OBJECT_free(sk);

    sk = (STACK_OF(ASN1_OBJECT)*)X509_get_ext_d2i(x509,
            NID_certificate_policies, &crit, NULL);
    #if !defined(WOLFSSL_SEP) && !defined(WOLFSSL_CERT_EXT)
        AssertNull(sk);
    #else
        /* AssertNotNull(sk); no cert policy set */
    #endif
    wolfSSL_sk_ASN1_OBJECT_free(sk);

    sk = (STACK_OF(ASN1_OBJECT)*)X509_get_ext_d2i(x509, NID_policy_mappings,
            &crit, NULL);
    /* AssertNotNull(sk); NID not yet supported */
    AssertIntEQ(crit, -1);
    wolfSSL_sk_ASN1_OBJECT_free(sk);

    sk = (STACK_OF(ASN1_OBJECT)*)X509_get_ext_d2i(x509, NID_policy_constraints,
            &crit, NULL);
    /* AssertNotNull(sk); NID not yet supported */
    AssertIntEQ(crit, -1);
    wolfSSL_sk_ASN1_OBJECT_free(sk);

    sk = (STACK_OF(ASN1_OBJECT)*)X509_get_ext_d2i(x509, NID_inhibit_any_policy,
            &crit, NULL);
    /* AssertNotNull(sk); NID not yet supported */
    AssertIntEQ(crit, -1);
    wolfSSL_sk_ASN1_OBJECT_free(sk);

    sk = (STACK_OF(ASN1_OBJECT)*)X509_get_ext_d2i(x509, NID_tlsfeature, &crit,
            NULL);
    /* AssertNotNull(sk); NID not yet supported */
    AssertIntEQ(crit, -1);
    wolfSSL_sk_ASN1_OBJECT_free(sk);

    /* test invalid cases */
    crit = 0;
    sk = (STACK_OF(ASN1_OBJECT)*)X509_get_ext_d2i(x509, -1, &crit, NULL);
    AssertNull(sk);
    AssertIntEQ(crit, -1);
    sk = (STACK_OF(ASN1_OBJECT)*)X509_get_ext_d2i(NULL, NID_tlsfeature,
            NULL, NULL);
    AssertNull(sk);

    AssertIntEQ(SSL_get_hit(ssl), 0);
    X509_free(x509);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    printf(resultFmt, passed);
    #endif /* defined(OPENSSL_EXTRA) && !defined(NO_CERTS) */
}


static void test_wolfSSL_private_keys(void)
{
    #if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
       !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    WOLFSSL*     ssl;
    WOLFSSL_CTX* ctx;
    EVP_PKEY* pkey = NULL;

    printf(testingFmt, "wolfSSL_private_keys()");

    OpenSSL_add_all_digests();
    OpenSSL_add_all_algorithms();

    AssertNotNull(ctx = SSL_CTX_new(wolfSSLv23_server_method()));
    AssertTrue(SSL_CTX_use_certificate_file(ctx, svrCert, SSL_FILETYPE_PEM));
    AssertTrue(SSL_CTX_use_PrivateKey_file(ctx, svrKey, SSL_FILETYPE_PEM));
    AssertNotNull(ssl = SSL_new(ctx));

    AssertIntEQ(wolfSSL_check_private_key(ssl), SSL_SUCCESS);

#ifdef USE_CERT_BUFFERS_2048
    {
    const unsigned char* server_key = (const unsigned char*)server_key_der_2048;

    AssertIntEQ(SSL_use_RSAPrivateKey_ASN1(ssl,
                (unsigned char*)client_key_der_2048,
                sizeof_client_key_der_2048), SSL_SUCCESS);
#ifndef HAVE_USER_RSA
    /* Should missmatch now that a different private key loaded */
    AssertIntNE(wolfSSL_check_private_key(ssl), SSL_SUCCESS);
#endif

    AssertIntEQ(SSL_use_PrivateKey_ASN1(0, ssl,
                (unsigned char*)server_key,
                sizeof_server_key_der_2048), SSL_SUCCESS);
    /* After loading back in DER format of original key, should match */
    AssertIntEQ(wolfSSL_check_private_key(ssl), SSL_SUCCESS);

    /* pkey not set yet, expecting to fail */
    AssertIntEQ(SSL_use_PrivateKey(ssl, pkey), SSL_FAILURE);

    /* set PKEY and test again */
    AssertNotNull(wolfSSL_d2i_PrivateKey(EVP_PKEY_RSA, &pkey,
                &server_key, (long)sizeof_server_key_der_2048));
    AssertIntEQ(SSL_use_PrivateKey(ssl, pkey), SSL_SUCCESS);

    /* reuse PKEY structure and test
     * this should be checked with a memory management sanity checker */
    AssertFalse(server_key == (const unsigned char*)server_key_der_2048);
    server_key = (const unsigned char*)server_key_der_2048;
    AssertNotNull(wolfSSL_d2i_PrivateKey(EVP_PKEY_RSA, &pkey,
                &server_key, (long)sizeof_server_key_der_2048));
    AssertIntEQ(SSL_use_PrivateKey(ssl, pkey), SSL_SUCCESS);
    }
#endif


    EVP_PKEY_free(pkey);
    SSL_free(ssl); /* frees x509 also since loaded into ssl */
    SSL_CTX_free(ctx);

    /* test existence of no-op macros in wolfssl/openssl/ssl.h */
    CONF_modules_free();
    ENGINE_cleanup();
    CONF_modules_unload();

    printf(resultFmt, passed);
    #endif /* defined(OPENSSL_EXTRA) && !defined(NO_CERTS) */
}


static void test_wolfSSL_PEM_PrivateKey(void)
{
    #if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
       !defined(NO_FILESYSTEM) && !defined(NO_RSA)   && \
       (defined(WOLFSSL_KEY_GEN) || defined(WOLFSSL_CERT_GEN)) && \
       defined(USE_CERT_BUFFERS_2048)
    const unsigned char* server_key = (const unsigned char*)server_key_der_2048;
    EVP_PKEY* pkey  = NULL;
    EVP_PKEY* pkey2 = NULL;
    BIO*      bio;
    unsigned char extra[10];
    int i;

    printf(testingFmt, "wolfSSL_PEM_PrivateKey()");

    XMEMSET(extra, 0, sizeof(extra));
    AssertNotNull(bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem()));
    AssertIntEQ(BIO_set_write_buf_size(bio, 4096), SSL_FAILURE);

    AssertNull(d2i_PrivateKey(EVP_PKEY_EC, &pkey,
            &server_key, (long)sizeof_server_key_der_2048));
    AssertNull(pkey);

    AssertNotNull(wolfSSL_d2i_PrivateKey(EVP_PKEY_RSA, &pkey,
            &server_key, (long)sizeof_server_key_der_2048));
    AssertIntEQ(PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL),
            SSL_SUCCESS);

    /* test of creating new EVP_PKEY */
    AssertNotNull((pkey2 = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL)));
    AssertIntEQ((int)XMEMCMP(pkey->pkey.ptr, pkey2->pkey.ptr, pkey->pkey_sz),0);

    /* test of reuse of EVP_PKEY */
    AssertNull(PEM_read_bio_PrivateKey(bio, &pkey, NULL, NULL));
    AssertIntEQ(BIO_pending(bio), 0);
    AssertIntEQ(PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL),
            SSL_SUCCESS);
    AssertIntEQ(BIO_write(bio, extra, 10), 10); /*add 10 extra bytes after PEM*/
    AssertNotNull(PEM_read_bio_PrivateKey(bio, &pkey, NULL, NULL));
    AssertNotNull(pkey);
    AssertIntEQ((int)XMEMCMP(pkey->pkey.ptr, pkey2->pkey.ptr, pkey->pkey_sz),0);
    AssertIntEQ(BIO_pending(bio), 10); /* check 10 extra bytes still there */
    AssertIntEQ(BIO_read(bio, extra, 10), 10);
    for (i = 0; i < 10; i++) {
        AssertIntEQ(extra[i], 0);
    }

    BIO_free(bio);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pkey2);

    #if !defined(NO_DES3) /* key is DES encrypted */
    {
        pem_password_cb* passwd_cb;
        void* passwd_cb_userdata;
        SSL_CTX* ctx;
        char passwd[] = "bad password";

        AssertNotNull(ctx = SSL_CTX_new(TLSv1_2_server_method()));

        AssertNotNull(bio = BIO_new_file("./certs/server-keyEnc.pem", "rb"));
        SSL_CTX_set_default_passwd_cb(ctx, &PasswordCallBack);
        AssertNotNull(passwd_cb = SSL_CTX_get_default_passwd_cb(ctx));
        AssertNull(passwd_cb_userdata =
            SSL_CTX_get_default_passwd_cb_userdata(ctx));

        /* fail case with password call back */
        AssertNull(pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL,
                    (void*)passwd));
        BIO_free(bio);
        AssertNotNull(bio = BIO_new_file("./certs/server-keyEnc.pem", "rb"));
        AssertNull(pkey = PEM_read_bio_PrivateKey(bio, NULL, passwd_cb,
                    (void*)passwd));
        BIO_free(bio);
        AssertNotNull(bio = BIO_new_file("./certs/server-keyEnc.pem", "rb"));

        /* use callback that works */
        AssertNotNull(pkey = PEM_read_bio_PrivateKey(bio, NULL, passwd_cb,
                (void*)"yassl123"));

        AssertIntEQ(SSL_CTX_use_PrivateKey(ctx, pkey), SSL_SUCCESS);

        EVP_PKEY_free(pkey);
        BIO_free(bio);
        SSL_CTX_free(ctx);
    }
    #endif /* !defined(NO_DES3) */

    #ifdef HAVE_ECC
    {
        unsigned char buf[2048];
        size_t bytes;
        XFILE f;
        SSL_CTX* ctx;

        AssertNotNull(ctx = SSL_CTX_new(TLSv1_2_server_method()));

        AssertNotNull(f = XFOPEN("./certs/ecc-key.der", "rb"));
        bytes = XFREAD(buf, 1, sizeof(buf), f);
        XFCLOSE(f);

        server_key = buf;
        pkey = NULL;
        AssertNull(d2i_PrivateKey(EVP_PKEY_RSA, &pkey, &server_key, bytes));
        AssertNull(pkey);
        AssertNotNull(d2i_PrivateKey(EVP_PKEY_EC, &pkey, &server_key, bytes));
        AssertIntEQ(SSL_CTX_use_PrivateKey(ctx, pkey), SSL_SUCCESS);

        EVP_PKEY_free(pkey);
        SSL_CTX_free(ctx);
    }
    #endif

    printf(resultFmt, passed);
    #endif /* defined(OPENSSL_EXTRA) && !defined(NO_CERTS) */
}


static void test_wolfSSL_tmp_dh(void)
{
    #if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
       !defined(NO_FILESYSTEM) && !defined(NO_DSA) && !defined(NO_RSA)
    byte buffer[5300];
    char file[] = "./certs/dsaparams.pem";
    FILE *f;
    int  bytes;
    DSA* dsa;
    DH*  dh;
    BIO*     bio;
    SSL*     ssl;
    SSL_CTX* ctx;

    printf(testingFmt, "wolfSSL_tmp_dh()");

    AssertNotNull(ctx = SSL_CTX_new(wolfSSLv23_server_method()));
    AssertTrue(SSL_CTX_use_certificate_file(ctx, svrCert, SSL_FILETYPE_PEM));
    AssertTrue(SSL_CTX_use_PrivateKey_file(ctx, svrKey, SSL_FILETYPE_PEM));
    AssertNotNull(ssl = SSL_new(ctx));

    f = fopen(file, "rb");
    AssertNotNull(f);
    bytes = (int)fread(buffer, 1, sizeof(buffer), f);
    fclose(f);

    bio = BIO_new_mem_buf((void*)buffer, bytes);
    AssertNotNull(bio);

    dsa = wolfSSL_PEM_read_bio_DSAparams(bio, NULL, NULL, NULL);
    AssertNotNull(dsa);

    dh = wolfSSL_DSA_dup_DH(dsa);
    AssertNotNull(dh);

    AssertIntEQ((int)SSL_CTX_set_tmp_dh(ctx, dh), SSL_SUCCESS);
    AssertIntEQ((int)SSL_set_tmp_dh(ssl, dh), SSL_SUCCESS);

    BIO_free(bio);
    DSA_free(dsa);
    DH_free(dh);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    printf(resultFmt, passed);
    #endif /* defined(OPENSSL_EXTRA) && !defined(NO_CERTS) */
}

static void test_wolfSSL_ctrl(void)
{
    #if defined(OPENSSL_EXTRA)
    byte buffer[5300];
    BIO* bio;
    int  bytes;
    BUF_MEM* ptr = NULL;

    printf(testingFmt, "wolfSSL_crtl()");

    bytes = sizeof(buffer);
    bio = BIO_new_mem_buf((void*)buffer, bytes);
    AssertNotNull(bio);
    AssertNotNull(BIO_s_socket());

    AssertIntEQ((int)wolfSSL_BIO_get_mem_ptr(bio, &ptr), SSL_SUCCESS);

    /* needs tested after stubs filled out @TODO
        SSL_ctrl
        SSL_CTX_ctrl
    */

    BIO_free(bio);
    printf(resultFmt, passed);
    #endif /* defined(OPENSSL_EXTRA) */
}


static void test_wolfSSL_CTX_add_extra_chain_cert(void)
{
    #if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
       !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    char caFile[] = "./certs/client-ca.pem";
    char clientFile[] = "./certs/client-cert.pem";
    SSL_CTX* ctx;
    X509* x509 = NULL;

    printf(testingFmt, "wolfSSL_CTX_add_extra_chain_cert()");

    AssertNotNull(ctx = SSL_CTX_new(wolfSSLv23_server_method()));

    x509 = wolfSSL_X509_load_certificate_file(caFile, SSL_FILETYPE_PEM);
    AssertNotNull(x509);
    AssertIntEQ((int)SSL_CTX_add_extra_chain_cert(ctx, x509), SSL_SUCCESS);

    x509 = wolfSSL_X509_load_certificate_file(clientFile, SSL_FILETYPE_PEM);
    AssertNotNull(x509);

    #if !defined(HAVE_USER_RSA) && !defined(HAVE_FAST_RSA)
    /* additional test of getting EVP_PKEY key size from X509
     * Do not run with user RSA because wolfSSL_RSA_size is not currently
     * allowed with user RSA */
    {
        EVP_PKEY* pkey;
        #if defined(HAVE_ECC)
        X509* ecX509;
        #endif /* HAVE_ECC */

        AssertNotNull(pkey = X509_get_pubkey(x509));
        /* current RSA key is 2048 bit (256 bytes) */
        AssertIntEQ(EVP_PKEY_size(pkey), 256);

        EVP_PKEY_free(pkey);

        #if defined(HAVE_ECC)
        #if defined(USE_CERT_BUFFERS_256)
        AssertNotNull(ecX509 = wolfSSL_X509_load_certificate_buffer(
                    cliecc_cert_der_256, sizeof_cliecc_cert_der_256,
                    SSL_FILETYPE_ASN1));
        #else
        AssertNotNull(ecX509 = wolfSSL_X509_load_certificate_file(cliEccCert,
                    SSL_FILETYPE_PEM));
        #endif
        AssertNotNull(pkey = X509_get_pubkey(ecX509));
        /* current ECC key is 256 bit (32 bytes) */
        AssertIntEQ(EVP_PKEY_size(pkey), 32);

        X509_free(ecX509);
        EVP_PKEY_free(pkey);
        #endif /* HAVE_ECC */
    }
    #endif /* !defined(HAVE_USER_RSA) && !defined(HAVE_FAST_RSA) */

    AssertIntEQ((int)SSL_CTX_add_extra_chain_cert(ctx, x509), SSL_SUCCESS);

    AssertNull(SSL_CTX_get_default_passwd_cb(ctx));
    AssertNull(SSL_CTX_get_default_passwd_cb_userdata(ctx));

    SSL_CTX_free(ctx);
    printf(resultFmt, passed);
    #endif /* defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
             !defined(NO_FILESYSTEM) && !defined(NO_RSA) */
}


static void test_wolfSSL_ERR_peek_last_error_line(void)
{
    #if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
       !defined(NO_FILESYSTEM) && defined(DEBUG_WOLFSSL) && \
       !defined(NO_OLD_TLS) && defined(HAVE_IO_TESTS_DEPENDENCIES)
    tcp_ready ready;
    func_args client_args;
    func_args server_args;
    THREAD_TYPE serverThread;
    callback_functions client_cb;
    callback_functions server_cb;
    int         line = 0;
    int         flag = ERR_TXT_STRING;
    const char* file = NULL;
    const char* data = NULL;

    printf(testingFmt, "wolfSSL_ERR_peek_last_error_line()");

    /* create a failed connection and inspect the error */
#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif
    XMEMSET(&client_args, 0, sizeof(func_args));
    XMEMSET(&server_args, 0, sizeof(func_args));

    StartTCP();
    InitTcpReady(&ready);

    client_cb.method  = wolfTLSv1_1_client_method;
    server_cb.method  = wolfTLSv1_2_server_method;

    server_args.signal    = &ready;
    server_args.callbacks = &server_cb;
    client_args.signal    = &ready;
    client_args.callbacks = &client_cb;

    start_thread(test_server_nofail, &server_args, &serverThread);
    wait_tcp_ready(&server_args);
    test_client_nofail(&client_args);
    join_thread(serverThread);

    FreeTcpReady(&ready);

    AssertIntGT(ERR_get_error_line_data(NULL, NULL, &data, &flag), 0);
    AssertNotNull(data);

    /* check clearing error state */
    ERR_remove_state(0);
    AssertIntEQ((int)ERR_peek_last_error_line(NULL, NULL), 0);
    ERR_peek_last_error_line(NULL, &line);
    AssertIntEQ(line, 0);
    ERR_peek_last_error_line(&file, NULL);
    AssertNull(file);

    /* retry connection to fill error queue */
    XMEMSET(&client_args, 0, sizeof(func_args));
    XMEMSET(&server_args, 0, sizeof(func_args));

    StartTCP();
    InitTcpReady(&ready);

    client_cb.method  = wolfTLSv1_1_client_method;
    server_cb.method  = wolfTLSv1_2_server_method;

    server_args.signal    = &ready;
    server_args.callbacks = &server_cb;
    client_args.signal    = &ready;
    client_args.callbacks = &client_cb;

    start_thread(test_server_nofail, &server_args, &serverThread);
    wait_tcp_ready(&server_args);
    test_client_nofail(&client_args);
    join_thread(serverThread);

    FreeTcpReady(&ready);

    /* check that error code was stored */
    AssertIntNE((int)ERR_peek_last_error_line(NULL, NULL), 0);
    ERR_peek_last_error_line(NULL, &line);
    AssertIntNE(line, 0);
    ERR_peek_last_error_line(&file, NULL);
    AssertNotNull(file);

#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif

    printf(resultFmt, passed);

    printf("\nTesting error print out\n");
    ERR_print_errors_fp(stdout);
    printf("Done testing print out\n\n");
    fflush(stdout);
    #endif /* defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
             !defined(NO_FILESYSTEM) && !defined(DEBUG_WOLFSSL) */
}


static void test_wolfSSL_X509_STORE_set_flags(void)
{
    #if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
       !defined(NO_FILESYSTEM) && !defined(NO_RSA)

    X509_STORE* store;
    X509* x509;

    printf(testingFmt, "wolfSSL_ERR_peek_last_error_line()");
    AssertNotNull((store = wolfSSL_X509_STORE_new()));
    AssertNotNull((x509 =
                wolfSSL_X509_load_certificate_file(svrCert, SSL_FILETYPE_PEM)));
    AssertIntEQ(X509_STORE_add_cert(store, x509), SSL_SUCCESS);

#ifdef HAVE_CRL
    AssertIntEQ(X509_STORE_set_flags(store, WOLFSSL_CRL_CHECKALL), SSL_SUCCESS);
#else
    AssertIntEQ(X509_STORE_set_flags(store, WOLFSSL_CRL_CHECKALL),
        NOT_COMPILED_IN);
#endif

    wolfSSL_X509_free(x509);
    wolfSSL_X509_STORE_free(store);

    printf(resultFmt, passed);
    #endif /* defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
             !defined(NO_FILESYSTEM) && !defined(NO_RSA) */
}


static void test_wolfSSL_BN(void)
{
    #if defined(OPENSSL_EXTRA) && !defined(NO_ASN)
    BIGNUM* a;
    BIGNUM* b;
    BIGNUM* c;
    BIGNUM* d;
    ASN1_INTEGER ai;
    unsigned char value[1];

    printf(testingFmt, "wolfSSL_BN()");

    AssertNotNull(b = BN_new());
    AssertNotNull(c = BN_new());
    AssertNotNull(d = BN_new());

    value[0] = 0x03;

    /* at the moment hard setting since no set function */
    ai.data[0] = 0x02; /* tag for ASN_INTEGER */
    ai.data[1] = 0x01; /* length of integer */
    ai.data[2] = value[0];

    AssertNotNull(a = ASN1_INTEGER_to_BN(&ai, NULL));

    value[0] = 0x02;
    AssertNotNull(BN_bin2bn(value, sizeof(value), b));

    value[0] = 0x05;
    AssertNotNull(BN_bin2bn(value, sizeof(value), c));

    /* a^b mod c = */
    AssertIntEQ(BN_mod_exp(d, NULL, b, c, NULL), SSL_FAILURE);
    AssertIntEQ(BN_mod_exp(d, a, b, c, NULL), SSL_SUCCESS);

    /* check result  3^2 mod 5 */
    value[0] = 0;
    AssertIntEQ(BN_bn2bin(d, value), SSL_SUCCESS);
    AssertIntEQ((int)(value[0] & 0x04), 4);

    AssertIntEQ(BN_set_word(a, 1), SSL_SUCCESS);
    AssertIntEQ(BN_set_word(b, 5), SSL_SUCCESS);
    AssertIntEQ(BN_sub(c, a, b), SSL_SUCCESS);
#if defined(WOLFSSL_KEY_GEN) || defined(HAVE_COMP_KEY)
    AssertNotNull(BN_bn2dec(c));
    AssertIntEQ(XMEMCMP(BN_bn2dec(c), "-4", sizeof("-4")), 0);
#endif
    AssertIntEQ(BN_get_word(c), 4);

    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_clear_free(d);

    printf(resultFmt, passed);
    #endif /* defined(OPENSSL_EXTRA) && !defined(NO_ASN) */
}

static void test_wolfSSL_BUF(void)
{
    #if defined(OPENSSL_EXTRA)
    BUF_MEM* buf;
    AssertNotNull(buf = BUF_MEM_new());
    AssertIntEQ(BUF_MEM_grow(buf, 10), 10);
    AssertIntEQ(BUF_MEM_grow(buf, -1), 0);
    BUF_MEM_free(buf);
    #endif /* OPENSSL_EXTRA */
}

static void test_wolfSSL_set_options(void)
{
    #if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
       !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    SSL*     ssl;
    SSL_CTX* ctx;
    char appData[] = "extra msg";

    printf(testingFmt, "wolfSSL_set_options()");

    AssertNotNull(ctx = SSL_CTX_new(wolfSSLv23_server_method()));
    AssertTrue(SSL_CTX_use_certificate_file(ctx, svrCert, SSL_FILETYPE_PEM));
    AssertTrue(SSL_CTX_use_PrivateKey_file(ctx, svrKey, SSL_FILETYPE_PEM));
    AssertNotNull(ssl = SSL_new(ctx));
#if defined(HAVE_EX_DATA) || defined(FORTRESS)
    AssertIntEQ(SSL_set_app_data(ssl, (void*)appData), SSL_SUCCESS);
    AssertNotNull(SSL_get_app_data((const WOLFSSL*)ssl));
    AssertIntEQ(XMEMCMP(SSL_get_app_data((const WOLFSSL*)ssl),
                appData, sizeof(appData)), 0);
#else
    AssertIntEQ(SSL_set_app_data(ssl, (void*)appData), SSL_FAILURE);
    AssertNull(SSL_get_app_data((const WOLFSSL*)ssl));
#endif

    AssertTrue(SSL_set_options(ssl, SSL_OP_NO_TLSv1) == SSL_OP_NO_TLSv1);
    AssertTrue(SSL_get_options(ssl) == SSL_OP_NO_TLSv1);

    AssertIntGT((int)SSL_set_options(ssl, (SSL_OP_COOKIE_EXCHANGE |
                                                          SSL_OP_NO_SSLv2)), 0);
    AssertTrue((SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE) &
                             SSL_OP_COOKIE_EXCHANGE) == SSL_OP_COOKIE_EXCHANGE);
    AssertTrue((SSL_set_options(ssl, SSL_OP_NO_TLSv1_2) &
                                       SSL_OP_NO_TLSv1_2) == SSL_OP_NO_TLSv1_2);
    AssertTrue((SSL_set_options(ssl, SSL_OP_NO_COMPRESSION) &
                               SSL_OP_NO_COMPRESSION) == SSL_OP_NO_COMPRESSION);

    SSL_free(ssl);
    SSL_CTX_free(ctx);

    printf(resultFmt, passed);
    #endif /* defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
             !defined(NO_FILESYSTEM) && !defined(NO_RSA) */
}


static void test_wolfSSL_PEM_read_bio(void)
{
    #if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
       !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    byte buffer[5300];
    FILE *f;
    int  bytes;
    X509* x509;
    BIO*  bio = NULL;

    printf(testingFmt, "wolfSSL_PEM_read_bio()");

    AssertNotNull(f = fopen(cliCert, "rb"));
    bytes = (int)fread(buffer, 1, sizeof(buffer), f);
    fclose(f);

    AssertNull(x509 = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL));
    AssertNotNull(bio = BIO_new_mem_buf((void*)buffer, bytes));
    AssertNotNull(x509 = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL));
    AssertIntEQ((int)BIO_set_fd(bio, 0, BIO_NOCLOSE), 1);

    BIO_free(bio);
    X509_free(x509);

    printf(resultFmt, passed);
    #endif /* defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
             !defined(NO_FILESYSTEM) && !defined(NO_RSA) */
}


static void test_wolfSSL_BIO(void)
{
    #if defined(OPENSSL_EXTRA)
    byte buffer[20];
    BIO* bio1;
    BIO* bio2;
    BIO* bio3;
    char* bufPt;
    int i;

    printf(testingFmt, "wolfSSL_BIO()");

    for (i = 0; i < 20; i++) {
        buffer[i] = i;
    }

    /* Creating and testing type BIO_s_bio */
    AssertNotNull(bio1 = BIO_new(BIO_s_bio()));
    AssertNotNull(bio2 = BIO_new(BIO_s_bio()));
    AssertNotNull(bio3 = BIO_new(BIO_s_bio()));

    /* read/write before set up */
    AssertIntEQ(BIO_read(bio1, buffer, 2),  WOLFSSL_BIO_UNSET);
    AssertIntEQ(BIO_write(bio1, buffer, 2), WOLFSSL_BIO_UNSET);

    AssertIntEQ(BIO_set_write_buf_size(bio1, 20), SSL_SUCCESS);
    AssertIntEQ(BIO_set_write_buf_size(bio2, 8),  SSL_SUCCESS);
    AssertIntEQ(BIO_make_bio_pair(bio1, bio2),    SSL_SUCCESS);

    AssertIntEQ(BIO_nwrite(bio1, &bufPt, 10), 10);
    XMEMCPY(bufPt, buffer, 10);
    AssertIntEQ(BIO_write(bio1, buffer + 10, 10), 10);
    /* write buffer full */
    AssertIntEQ(BIO_write(bio1, buffer, 10), WOLFSSL_BIO_ERROR);
    AssertIntEQ(BIO_flush(bio1), SSL_SUCCESS);
    AssertIntEQ((int)BIO_ctrl_pending(bio1), 0);

    /* write the other direction with pair */
    AssertIntEQ((int)BIO_nwrite(bio2, &bufPt, 10), 8);
    XMEMCPY(bufPt, buffer, 8);
    AssertIntEQ(BIO_write(bio2, buffer, 10), WOLFSSL_BIO_ERROR);

    /* try read */
    AssertIntEQ((int)BIO_ctrl_pending(bio1), 8);
    AssertIntEQ((int)BIO_ctrl_pending(bio2), 20);

    AssertIntEQ(BIO_nread(bio2, &bufPt, (int)BIO_ctrl_pending(bio2)), 20);
    for (i = 0; i < 20; i++) {
        AssertIntEQ((int)bufPt[i], i);
    }
    AssertIntEQ(BIO_nread(bio2, &bufPt, 1), WOLFSSL_BIO_ERROR);
    AssertIntEQ(BIO_nread(bio1, &bufPt, (int)BIO_ctrl_pending(bio1)), 8);
    for (i = 0; i < 8; i++) {
        AssertIntEQ((int)bufPt[i], i);
    }
    AssertIntEQ(BIO_nread(bio1, &bufPt, 1), WOLFSSL_BIO_ERROR);
    AssertIntEQ(BIO_ctrl_reset_read_request(bio1), 1);

    /* new pair */
    AssertIntEQ(BIO_make_bio_pair(bio1, bio3), SSL_FAILURE);
    BIO_free(bio2); /* free bio2 and automaticly remove from pair */
    AssertIntEQ(BIO_make_bio_pair(bio1, bio3), SSL_SUCCESS);
    AssertIntEQ((int)BIO_ctrl_pending(bio3), 0);
    AssertIntEQ(BIO_nread(bio3, &bufPt, 10), WOLFSSL_BIO_ERROR);

    /* test wrap around... */
    AssertIntEQ(BIO_reset(bio1), 0);
    AssertIntEQ(BIO_reset(bio3), 0);

    /* fill write buffer, read only small amount then write again */
    AssertIntEQ(BIO_nwrite(bio1, &bufPt, 20), 20);
    XMEMCPY(bufPt, buffer, 20);
    AssertIntEQ(BIO_nread(bio3, &bufPt, 4), 4);
    for (i = 0; i < 4; i++) {
        AssertIntEQ(bufPt[i], i);
    }

    /* try writing over read index */
    AssertIntEQ(BIO_nwrite(bio1, &bufPt, 5), 4);
    XMEMSET(bufPt, 0, 4);
    AssertIntEQ((int)BIO_ctrl_pending(bio3), 20);

    /* read and write 0 bytes */
    AssertIntEQ(BIO_nread(bio3, &bufPt, 0), 0);
    AssertIntEQ(BIO_nwrite(bio1, &bufPt, 0), 0);

    /* should read only to end of write buffer then need to read again */
    AssertIntEQ(BIO_nread(bio3, &bufPt, 20), 16);
    for (i = 0; i < 16; i++) {
        AssertIntEQ(bufPt[i], buffer[4 + i]);
    }

    AssertIntEQ(BIO_nread(bio3, NULL, 0), SSL_FAILURE);
    AssertIntEQ(BIO_nread0(bio3, &bufPt), 4);
    for (i = 0; i < 4; i++) {
        AssertIntEQ(bufPt[i], 0);
    }

    /* read index should not have advanced with nread0 */
    AssertIntEQ(BIO_nread(bio3, &bufPt, 5), 4);
    for (i = 0; i < 4; i++) {
        AssertIntEQ(bufPt[i], 0);
    }

    /* write and fill up buffer checking reset of index state */
    AssertIntEQ(BIO_nwrite(bio1, &bufPt, 20), 20);
    XMEMCPY(bufPt, buffer, 20);

    /* test reset on data in bio1 write buffer */
    AssertIntEQ(BIO_reset(bio1), 0);
    AssertIntEQ((int)BIO_ctrl_pending(bio3), 0);
    AssertIntEQ(BIO_nread(bio3, &bufPt, 3), WOLFSSL_BIO_ERROR);
    AssertIntEQ(BIO_nwrite(bio1, &bufPt, 20), 20);
    XMEMCPY(bufPt, buffer, 20);
    AssertIntEQ(BIO_nread(bio3, &bufPt, 6), 6);
    for (i = 0; i < 6; i++) {
        AssertIntEQ(bufPt[i], i);
    }

    /* test case of writing twice with offset read index */
    AssertIntEQ(BIO_nwrite(bio1, &bufPt, 3), 3);
    AssertIntEQ(BIO_nwrite(bio1, &bufPt, 4), 3); /* try overwriting */
    AssertIntEQ(BIO_nwrite(bio1, &bufPt, 4), WOLFSSL_BIO_ERROR);
    AssertIntEQ(BIO_nread(bio3, &bufPt, 0), 0);
    AssertIntEQ(BIO_nwrite(bio1, &bufPt, 4), WOLFSSL_BIO_ERROR);
    AssertIntEQ(BIO_nread(bio3, &bufPt, 1), 1);
    AssertIntEQ(BIO_nwrite(bio1, &bufPt, 4), 1);
    AssertIntEQ(BIO_nwrite(bio1, &bufPt, 4), WOLFSSL_BIO_ERROR);

    BIO_free(bio1);
    BIO_free(bio3);

    /* BIOs with file pointers */
    #if !defined(NO_FILESYSTEM)
    {
        XFILE f1;
        XFILE f2;
        BIO*  f_bio1;
        BIO*  f_bio2;
        unsigned char cert[300];
        char testFile[] = "tests/bio_write_test.txt";
        char msg[]      = "bio_write_test.txt contains the first 300 bytes of certs/server-cert.pem\ncreated by tests/unit.test\n\n";

        AssertNotNull(f_bio1 = BIO_new(BIO_s_file()));
        AssertNotNull(f_bio2 = BIO_new(BIO_s_file()));

        AssertIntEQ((int)BIO_set_mem_eof_return(f_bio1, -1), 0);
        AssertIntEQ((int)BIO_set_mem_eof_return(NULL, -1),   0);

        f1 = XFOPEN(svrCert, "rwb");
        AssertIntEQ((int)BIO_set_fp(f_bio1, f1, BIO_CLOSE), SSL_SUCCESS);
        AssertIntEQ(BIO_write_filename(f_bio2, testFile),
                SSL_SUCCESS);

        AssertIntEQ(BIO_read(f_bio1, cert, sizeof(cert)), sizeof(cert));
        AssertIntEQ(BIO_write(f_bio2, msg, sizeof(msg)), sizeof(msg));
        AssertIntEQ(BIO_write(f_bio2, cert, sizeof(cert)), sizeof(cert));

        AssertIntEQ((int)BIO_get_fp(f_bio2, &f2), SSL_SUCCESS);
        AssertIntEQ(BIO_reset(f_bio2), 0);
        AssertIntEQ(BIO_seek(f_bio2, 4), 0);

        BIO_free(f_bio1);
        BIO_free(f_bio2);

        AssertNotNull(f_bio1 = BIO_new_file(svrCert, "rwb"));
        AssertIntEQ((int)BIO_set_mem_eof_return(f_bio1, -1), 0);
        AssertIntEQ(BIO_read(f_bio1, cert, sizeof(cert)), sizeof(cert));
        BIO_free(f_bio1);

    }
    #endif /* !defined(NO_FILESYSTEM) */

    printf(resultFmt, passed);
    #endif
}


static void test_wolfSSL_ASN1_STRING(void)
{
    #if defined(OPENSSL_EXTRA)
    ASN1_STRING* str = NULL;
    const char data[] = "hello wolfSSL";

    printf(testingFmt, "wolfSSL_ASN1_STRING()");

    AssertNotNull(str = ASN1_STRING_type_new(V_ASN1_OCTET_STRING));
    AssertIntEQ(ASN1_STRING_set(str, (const void*)data, sizeof(data)), 1);
    AssertIntEQ(ASN1_STRING_set(str, (const void*)data, -1), 1);
    AssertIntEQ(ASN1_STRING_set(str, NULL, -1), 0);

    ASN1_STRING_free(str);

    printf(resultFmt, passed);
    #endif
}


static void test_wolfSSL_X509(void)
{
    #if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && !defined(NO_FILESYSTEM)\
    && !defined(NO_RSA)
    X509* x509;
    BIO*  bio;
    X509_STORE_CTX* ctx;
    X509_STORE* store;

    printf(testingFmt, "wolfSSL_X509()");

    AssertNotNull(x509 = X509_new());
    X509_free(x509);

    x509 = wolfSSL_X509_load_certificate_file(cliCert, SSL_FILETYPE_PEM);

    AssertNotNull(bio = BIO_new(BIO_s_mem()));

    AssertIntEQ(i2d_X509_bio(bio, x509), SSL_SUCCESS);

    AssertNotNull(ctx = X509_STORE_CTX_new());

    AssertIntEQ(X509_verify_cert(ctx), SSL_FATAL_ERROR);

    AssertNotNull(store = X509_STORE_new());
    AssertIntEQ(X509_STORE_add_cert(store, x509), SSL_SUCCESS);
    AssertIntEQ(X509_STORE_CTX_init(ctx, store, x509, NULL), SSL_SUCCESS);
    AssertIntEQ(X509_verify_cert(ctx), SSL_SUCCESS);


    X509_STORE_CTX_free(ctx);
    BIO_free(bio);

    printf(resultFmt, passed);
    #endif
}


static void test_wolfSSL_RAND(void)
{
    #if defined(OPENSSL_EXTRA)
    byte seed[16];

    printf(testingFmt, "wolfSSL_RAND()");

    RAND_seed(seed, sizeof(seed));
    RAND_cleanup();

    AssertIntEQ(RAND_egd(NULL), -1);
#ifndef NO_FILESYSTEM
    {
        char fname[100];

        AssertNotNull(RAND_file_name(fname, sizeof(fname)));
        AssertIntEQ(RAND_write_file(NULL), 0);
    }
#endif

    printf(resultFmt, passed);
    #endif
}


static void test_wolfSSL_pseudo_rand(void)
{
    #if defined(OPENSSL_EXTRA)
    BIGNUM* bn;
    unsigned char bin[8];
    int i;

    printf(testingFmt, "wolfSSL_pseudo_rand()");

    /* BN_pseudo_rand returns 1 on success 0 on failure
     * int BN_pseudo_rand(BIGNUM* bn, int bits, int top, int bottom) */
    for (i = 0; i < 10; i++) {
        AssertNotNull(bn = BN_new());
        AssertIntEQ(BN_pseudo_rand(bn, 8, 0, 0), SSL_SUCCESS);
        AssertIntGT(BN_bn2bin(bn, bin),0);
        AssertIntEQ((bin[0] & 0x80), 0x80); /* top bit should be set */
        BN_free(bn);
    }

    for (i = 0; i < 10; i++) {
        AssertNotNull(bn = BN_new());
        AssertIntEQ(BN_pseudo_rand(bn, 8, 1, 1), SSL_SUCCESS);
        AssertIntGT(BN_bn2bin(bn, bin),0);
        AssertIntEQ((bin[0] & 0xc1), 0xc1); /* top bit should be set */
        BN_free(bn);
    }

    printf(resultFmt, passed);
    #endif
}

static void test_wolfSSL_pkcs8(void)
{
    #if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM) && defined(HAVE_ECC)
    PKCS8_PRIV_KEY_INFO* pt;
    BIO* bio;
    FILE* f;
    int bytes;
    char buffer[512];

    printf(testingFmt, "wolfSSL_pkcs8()");

    /* file from wolfssl/certs/ directory */
    AssertNotNull(f = fopen("./certs/ecc-keyPkcs8.pem", "rb"));
    AssertIntGT((bytes = (int)fread(buffer, 1, sizeof(buffer), f)), 0);
    fclose(f);
    AssertNotNull(bio = BIO_new_mem_buf((void*)buffer, bytes));
    AssertNotNull(pt = d2i_PKCS8_PRIV_KEY_INFO_bio(bio, NULL));
    BIO_free(bio);
    PKCS8_PRIV_KEY_INFO_free(pt);

    printf(resultFmt, passed);
    #endif
}


static void test_wolfSSL_ERR_put_error(void)
{
    #if defined(OPENSSL_EXTRA) && defined(DEBUG_WOLFSSL)
    const char* file;
    int line;

    printf(testingFmt, "wolfSSL_ERR_put_error()");

    ERR_put_error(0,SYS_F_ACCEPT, 0, "this file", 0);
    AssertIntEQ(ERR_get_error_line(&file, &line), 0);
    ERR_put_error(0,SYS_F_BIND, 1, "this file", 1);
    AssertIntEQ(ERR_get_error_line(&file, &line), 1);
    ERR_put_error(0,SYS_F_CONNECT, 2, "this file", 2);
    AssertIntEQ(ERR_get_error_line(&file, &line), 2);
    ERR_put_error(0,SYS_F_FOPEN, 3, "this file", 3);
    AssertIntEQ(ERR_get_error_line(&file, &line), 3);
    ERR_put_error(0,SYS_F_FREAD, 4, "this file", 4);
    AssertIntEQ(ERR_get_error_line(&file, &line), 4);
    ERR_put_error(0,SYS_F_GETADDRINFO, 5, "this file", 5);
    AssertIntEQ(ERR_get_error_line(&file, &line), 5);
    ERR_put_error(0,SYS_F_GETSOCKOPT, 6, "this file", 6);
    AssertIntEQ(ERR_get_error_line(&file, &line), 6);
    ERR_put_error(0,SYS_F_GETSOCKNAME, 7, "this file", 7);
    AssertIntEQ(ERR_get_error_line(&file, &line), 7);
    ERR_put_error(0,SYS_F_GETHOSTBYNAME, 8, "this file", 8);
    AssertIntEQ(ERR_get_error_line(&file, &line), 8);
    ERR_put_error(0,SYS_F_GETNAMEINFO, 9, "this file", 9);
    AssertIntEQ(ERR_get_error_line(&file, &line), 9);
    ERR_put_error(0,SYS_F_GETSERVBYNAME, 10, "this file", 10);
    AssertIntEQ(ERR_get_error_line(&file, &line), 10);
    ERR_put_error(0,SYS_F_IOCTLSOCKET, 11, "this file", 11);
    AssertIntEQ(ERR_get_error_line(&file, &line), 11);
    ERR_put_error(0,SYS_F_LISTEN, 12, "this file", 12);
    AssertIntEQ(ERR_get_error_line(&file, &line), 12);
    ERR_put_error(0,SYS_F_OPENDIR, 13, "this file", 13);
    AssertIntEQ(ERR_get_error_line(&file, &line), 13);
    ERR_put_error(0,SYS_F_SETSOCKOPT, 14, "this file", 14);
    AssertIntEQ(ERR_get_error_line(&file, &line), 14);
    ERR_put_error(0,SYS_F_SOCKET, 15, "this file", 15);
    AssertIntEQ(ERR_get_error_line(&file, &line), 15);

    /* try reading past end of error queue */
    file = NULL;
    AssertIntEQ(ERR_get_error_line(&file, &line), 0);
    AssertNull(file);

    printf(resultFmt, passed);
    #endif
}


static void test_wolfSSL_HMAC(void)
{
    #if defined(OPENSSL_EXTRA) && !defined(NO_SHA256)
    HMAC_CTX hmac;
    ENGINE* e = NULL;
    const unsigned char key[] = "simple test key";
    unsigned char hash[MAX_DIGEST_SIZE];
    unsigned int len;


    printf(testingFmt, "wolfSSL_HMAC()");

    HMAC_CTX_init(&hmac);
    AssertIntEQ(HMAC_Init_ex(&hmac, (void*)key, (int)sizeof(key),
                EVP_sha256(), e), SSL_SUCCESS);

    /* re-using test key as data to hash */
    AssertIntEQ(HMAC_Update(&hmac, key, (int)sizeof(key)), SSL_SUCCESS);
    AssertIntEQ(HMAC_Update(&hmac, NULL, 0), SSL_SUCCESS);
    AssertIntEQ(HMAC_Final(&hmac, hash, &len), SSL_SUCCESS);
    AssertIntEQ(len, (int)SHA256_DIGEST_SIZE);

    HMAC_cleanup(&hmac);

    printf(resultFmt, passed);
    #endif
}


static void test_wolfSSL_OBJ(void)
{
    #if defined(OPENSSL_EXTRA) && !defined(NO_SHA256)
    ASN1_OBJECT* obj = NULL;
    char buf[50];

    printf(testingFmt, "wolfSSL_OBJ()");

    AssertIntEQ(OBJ_obj2txt(buf, (int)sizeof(buf), obj, 1), SSL_FAILURE);
    AssertNotNull(obj = OBJ_nid2obj(NID_any_policy));
    AssertIntEQ(OBJ_obj2nid(obj), NID_any_policy);
    AssertIntEQ(OBJ_obj2txt(buf, (int)sizeof(buf), obj, 1), 11);
    AssertIntGT(OBJ_obj2txt(buf, (int)sizeof(buf), obj, 0), 0);
    ASN1_OBJECT_free(obj);

    AssertNotNull(obj = OBJ_nid2obj(NID_sha256));
    AssertIntEQ(OBJ_obj2nid(obj), NID_sha256);
    AssertIntEQ(OBJ_obj2txt(buf, (int)sizeof(buf), obj, 1), 22);
    AssertIntGT(OBJ_obj2txt(buf, (int)sizeof(buf), obj, 0), 0);
    ASN1_OBJECT_free(obj);

    printf(resultFmt, passed);
    #endif
}


static void test_wolfSSL_X509_NAME_ENTRY(void)
{
    #if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) \
    && !defined(NO_FILESYSTEM) && !defined(NO_RSA) && defined(WOLFSSL_CERT_GEN)
    X509*      x509;
    BIO*       bio;
    X509_NAME* nm;
    X509_NAME_ENTRY* entry;
    unsigned char cn[] = "another name to add";


    printf(testingFmt, "wolfSSL_X509_NAME_ENTRY()");

    AssertNotNull(x509 =
            wolfSSL_X509_load_certificate_file(cliCert, SSL_FILETYPE_PEM));
    AssertNotNull(bio = BIO_new(BIO_s_mem()));
    AssertIntEQ(PEM_write_bio_X509_AUX(bio, x509), SSL_SUCCESS);

#ifdef WOLFSSL_CERT_REQ
    {
        X509_REQ* req;
        BIO*      bReq;

        AssertNotNull(req =
            wolfSSL_X509_load_certificate_file(cliCert, SSL_FILETYPE_PEM));
        AssertNotNull(bReq = BIO_new(BIO_s_mem()));
        AssertIntEQ(PEM_write_bio_X509_REQ(bReq, req), SSL_SUCCESS);

        BIO_free(bReq);
        X509_free(req);
    }
#endif

    AssertNotNull(nm = X509_get_subject_name(x509));
    AssertNotNull(entry = X509_NAME_ENTRY_create_by_NID(NULL, NID_commonName,
                0x0c, cn, (int)sizeof(cn)));
    AssertIntEQ(X509_NAME_add_entry(nm, entry, -1, 0), SSL_SUCCESS);


    X509_NAME_ENTRY_free(entry);
    BIO_free(bio);
    X509_free(x509);

    printf(resultFmt, passed);
    #endif
}


static void test_wolfSSL_BIO_gets(void)
{
    #if defined(OPENSSL_EXTRA)
    BIO* bio;
    BIO* bio2;
    char msg[] = "\nhello wolfSSL\n security plus\t---...**adf\na...b.c";
    char emp[] = "";
    char buffer[20];
    int bufferSz = 20;

    printf(testingFmt, "wolfSSL_X509_BIO_gets()");

    AssertNotNull(bio = BIO_new_mem_buf((void*)msg, sizeof(msg)));
    XMEMSET(buffer, 0, bufferSz);
    AssertNotNull(BIO_push(bio, BIO_new(BIO_s_bio())));
    AssertNull(bio2 = BIO_find_type(bio, BIO_TYPE_FILE));
    AssertNotNull(bio2 = BIO_find_type(bio, BIO_TYPE_BIO));
    AssertFalse(bio2 != BIO_next(bio));

    /* make buffer filled with no terminating characters */
    XMEMSET(buffer, 1, bufferSz);

    /* BIO_gets reads a line of data */
    AssertIntEQ(BIO_gets(bio, buffer, -3), 0);
    AssertIntEQ(BIO_gets(bio, buffer, bufferSz), 1);
    AssertIntEQ(BIO_gets(bio, buffer, bufferSz), 14);
    AssertStrEQ(buffer, "hello wolfSSL\n");
    AssertIntEQ(BIO_gets(bio, buffer, bufferSz), 19);
    AssertIntEQ(BIO_gets(bio, buffer, bufferSz), 8);
    AssertIntEQ(BIO_gets(bio, buffer, -1), 0);

    /* check not null terminated string */
    BIO_free(bio);
    msg[0] = 0x33;
    msg[1] = 0x33;
    msg[2] = 0x33;
    AssertNotNull(bio = BIO_new_mem_buf((void*)msg, 3));
    AssertIntEQ(BIO_gets(bio, buffer, 3), 2);
    AssertIntEQ(buffer[0], msg[0]);
    AssertIntEQ(buffer[1], msg[1]);
    AssertIntNE(buffer[2], msg[2]);

    BIO_free(bio);
    msg[3]    = 0x33;
    buffer[3] = 0x33;
    AssertNotNull(bio = BIO_new_mem_buf((void*)msg, 3));
    AssertIntEQ(BIO_gets(bio, buffer, bufferSz), 3);
    AssertIntEQ(buffer[0], msg[0]);
    AssertIntEQ(buffer[1], msg[1]);
    AssertIntEQ(buffer[2], msg[2]);
    AssertIntNE(buffer[3], 0x33); /* make sure null terminator was set */

    /* check reading an empty string */
    BIO_free(bio);
    AssertNotNull(bio = BIO_new_mem_buf((void*)emp, sizeof(emp)));
    AssertIntEQ(BIO_gets(bio, buffer, bufferSz), 1); /* just terminator */
    AssertStrEQ(emp, buffer);

    /* check error cases */
    BIO_free(bio);
    AssertIntEQ(BIO_gets(NULL, NULL, 0), SSL_FAILURE);
    AssertNotNull(bio = BIO_new(BIO_s_mem()));
    AssertIntEQ(BIO_gets(bio, buffer, 2), -1); /* nothing to read */

#if !defined(NO_FILESYSTEM)
    {
        BIO*  f_bio;
        XFILE f;
        AssertNotNull(f_bio = BIO_new(BIO_s_file()));
        AssertIntLE(BIO_gets(f_bio, buffer, bufferSz), 0);

        f = XFOPEN(svrCert, "rb");
        AssertIntEQ((int)BIO_set_fp(f_bio, f, BIO_CLOSE), SSL_SUCCESS);
        AssertIntGT(BIO_gets(f_bio, buffer, bufferSz), 0);

        BIO_free(f_bio);
    }
#endif /* NO_FILESYSTEM */

    BIO_free(bio);
    BIO_free(bio2);

    /* try with type BIO */
    XMEMCPY(msg, "\nhello wolfSSL\n security plus\t---...**adf\na...b.c",
            sizeof(msg));
    AssertNotNull(bio = BIO_new(BIO_s_bio()));
    AssertNotNull(bio2 = BIO_new(BIO_s_bio()));

    AssertIntEQ(BIO_set_write_buf_size(bio, 10),           SSL_SUCCESS);
    AssertIntEQ(BIO_set_write_buf_size(bio2, sizeof(msg)), SSL_SUCCESS);
    AssertIntEQ(BIO_make_bio_pair(bio, bio2),              SSL_SUCCESS);

    AssertIntEQ(BIO_write(bio2, msg, sizeof(msg)), sizeof(msg));
    AssertIntEQ(BIO_gets(bio, buffer, -3), 0);
    AssertIntEQ(BIO_gets(bio, buffer, bufferSz), 1);
    AssertIntEQ(BIO_gets(bio, buffer, bufferSz), 14);
    AssertStrEQ(buffer, "hello wolfSSL\n");
    AssertIntEQ(BIO_gets(bio, buffer, bufferSz), 19);
    AssertIntEQ(BIO_gets(bio, buffer, bufferSz), 8);
    AssertIntEQ(BIO_gets(bio, buffer, -1), 0);

    BIO_free(bio);
    BIO_free(bio2);

    printf(resultFmt, passed);
    #endif
}


static void test_wolfSSL_BIO_write(void)
{
    #if defined(OPENSSL_EXTRA) && defined(WOLFSSL_BASE64_ENCODE)
    BIO* bio;
    BIO* bio64;
    BIO* ptr;
    int  sz;
    char msg[] = "conversion test";
    char out[40];
    char expected[] = "Y29udmVyc2lvbiB0ZXN0AA==\n";

    printf(testingFmt, "wolfSSL_BIO_write()");

    AssertNotNull(bio64 = BIO_new(BIO_f_base64()));
    AssertNotNull(bio   = BIO_push(bio64, BIO_new(BIO_s_mem())));

    /* now should convert to base64 then write to memory */
    AssertIntEQ(BIO_write(bio, msg, sizeof(msg)), 25);
    BIO_flush(bio);
    AssertNotNull(ptr = BIO_find_type(bio, BIO_TYPE_MEM));
    sz = sizeof(out);
    XMEMSET(out, 0, sz);
    AssertIntEQ((sz = BIO_read(ptr, out, sz)), 25);
    AssertIntEQ(XMEMCMP(out, expected, sz), 0);

    /* write then read should return the same message */
    AssertIntEQ(BIO_write(bio, msg, sizeof(msg)), 25);
    sz = sizeof(out);
    XMEMSET(out, 0, sz);
    AssertIntEQ(BIO_read(bio, out, sz), 16);
    AssertIntEQ(XMEMCMP(out, msg, sizeof(msg)), 0);

    /* now try encoding with no line ending */
    BIO_set_flags(bio64, BIO_FLAG_BASE64_NO_NL);
    AssertIntEQ(BIO_write(bio, msg, sizeof(msg)), 24);
    BIO_flush(bio);
    sz = sizeof(out);
    XMEMSET(out, 0, sz);
    AssertIntEQ((sz = BIO_read(ptr, out, sz)), 24);
    AssertIntEQ(XMEMCMP(out, expected, sz), 0);

    BIO_free_all(bio); /* frees bio64 also */

    /* test with more than one bio64 in list */
    AssertNotNull(bio64 = BIO_new(BIO_f_base64()));
    AssertNotNull(bio   = BIO_push(BIO_new(BIO_f_base64()), bio64));
    AssertNotNull(BIO_push(bio64, BIO_new(BIO_s_mem())));

    /* now should convert to base64(x2) when stored and then decode with read */
    AssertIntEQ(BIO_write(bio, msg, sizeof(msg)), 37);
    BIO_flush(bio);
    sz = sizeof(out);
    XMEMSET(out, 0, sz);
    AssertIntEQ((sz = BIO_read(bio, out, sz)), 16);
    AssertIntEQ(XMEMCMP(out, msg, sz), 0);
    BIO_free_all(bio); /* frees bio64s also */

    printf(resultFmt, passed);
    #endif
}

static void test_wolfSSL_SESSION(void)
{
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && \
    !defined(NO_RSA) && defined(HAVE_EXT_CACHE) && \
    defined(HAVE_IO_TESTS_DEPENDENCIES)

    WOLFSSL*     ssl;
    WOLFSSL_CTX* ctx;
    WOLFSSL_SESSION* sess;
    const unsigned char context[] = "user app context";
    unsigned char* sessDer = NULL;
    unsigned char* ptr     = NULL;
    unsigned int contextSz = (unsigned int)sizeof(context);
    int ret, err, sockfd, sz;
    tcp_ready ready;
    func_args server_args;
    THREAD_TYPE serverThread;

    printf(testingFmt, "wolfSSL_SESSION()");
    AssertNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));

    AssertTrue(wolfSSL_CTX_use_certificate_file(ctx, cliCert, SSL_FILETYPE_PEM));
    AssertTrue(wolfSSL_CTX_use_PrivateKey_file(ctx, cliKey, SSL_FILETYPE_PEM));
    AssertIntEQ(wolfSSL_CTX_load_verify_locations(ctx, caCert, 0), SSL_SUCCESS);
    wolfSSL_CTX_set_default_passwd_cb(ctx, PasswordCallBack);


    XMEMSET(&server_args, 0, sizeof(func_args));
#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif

    StartTCP();
    InitTcpReady(&ready);

#if defined(USE_WINDOWS_API)
    /* use RNG to get random port if using windows */
    ready.port = GetRandomPort();
#endif

    server_args.signal = &ready;
    start_thread(test_server_nofail, &server_args, &serverThread);
    wait_tcp_ready(&server_args);

    /* client connection */
    ssl = wolfSSL_new(ctx);
    tcp_connect(&sockfd, wolfSSLIP, ready.port, 0, 0, ssl);
    AssertIntEQ(wolfSSL_set_fd(ssl, sockfd), SSL_SUCCESS);

    do {
#ifdef WOLFSSL_ASYNC_CRYPT
        if (err == WC_PENDING_E) {
            ret = wolfSSL_AsyncPoll(ssl, WOLF_POLL_FLAG_CHECK_HW);
            if (ret < 0) { break; } else if (ret == 0) { continue; }
        }
#endif

        err = 0; /* Reset error */
        ret = wolfSSL_connect(ssl);
        if (ret != SSL_SUCCESS) {
            err = wolfSSL_get_error(ssl, 0);
        }
    } while (ret != SSL_SUCCESS && err == WC_PENDING_E);
    AssertIntEQ(ret, SSL_SUCCESS);
    sess = wolfSSL_get_session(ssl);
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);

    join_thread(serverThread);

    FreeTcpReady(&ready);

#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif

    /* get session from DER and update the timeout */
    AssertIntEQ(wolfSSL_i2d_SSL_SESSION(NULL, &sessDer), BAD_FUNC_ARG);
    AssertIntGT((sz = wolfSSL_i2d_SSL_SESSION(sess, &sessDer)), 0);
    wolfSSL_SESSION_free(sess);
    ptr = sessDer;
    AssertNull(sess = wolfSSL_d2i_SSL_SESSION(NULL, NULL, sz));
    AssertNotNull(sess = wolfSSL_d2i_SSL_SESSION(NULL,
                (const unsigned char**)&ptr, sz));
    XFREE(sessDer, NULL, DYNAMIC_TYPE_OPENSSL);
    AssertIntGT(wolfSSL_SESSION_get_time(sess), 0);
    AssertIntEQ(wolfSSL_SSL_SESSION_set_timeout(sess, 500), SSL_SUCCESS);

    /* successful set session test */
    AssertNotNull(ssl = wolfSSL_new(ctx));
    AssertIntEQ(wolfSSL_set_session(ssl, sess), SSL_SUCCESS);

    /* fail case with miss match session context IDs (use compatibility API) */
    AssertIntEQ(SSL_set_session_id_context(ssl, context, contextSz),
            SSL_SUCCESS);
    AssertIntEQ(wolfSSL_set_session(ssl, sess), SSL_FAILURE);
    wolfSSL_free(ssl);
    AssertIntEQ(SSL_CTX_set_session_id_context(NULL, context, contextSz),
            SSL_FAILURE);
    AssertIntEQ(SSL_CTX_set_session_id_context(ctx, context, contextSz),
            SSL_SUCCESS);
    AssertNotNull(ssl = wolfSSL_new(ctx));
    AssertIntEQ(wolfSSL_set_session(ssl, sess), SSL_FAILURE);
    wolfSSL_free(ssl);

    SSL_SESSION_free(sess);
    wolfSSL_CTX_free(ctx);
    printf(resultFmt, passed);
#endif
}

static void test_wolfSSL_sk_GENERAL_NAME(void)
{
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && \
    !defined(NO_RSA)
    X509* x509;
    unsigned char buf[4096];
    const unsigned char* bufPt;
    int bytes;
    XFILE f;
    STACK_OF(GENERAL_NAME)* sk;

    printf(testingFmt, "wolfSSL_sk_GENERAL_NAME()");

    AssertNotNull(f = XFOPEN(cliCertDer, "rb"));
    AssertIntGT((bytes = (int)XFREAD(buf, 1, sizeof(buf), f)), 0);
    XFCLOSE(f);

    bufPt = buf;
    AssertNotNull(x509 = d2i_X509(NULL, &bufPt, bytes));

    /* current cert has no alt names */
    AssertNull(sk = X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL));

    AssertIntEQ(sk_GENERAL_NAME_num(sk), 0);
#if 0
    for (i = 0; i < sk_GENERAL_NAME_num(sk); i++) {
        GENERAL_NAME* gn = sk_GENERAL_NAME_value(sk, i);
        if (gn == NULL) {
            printf("massive falure\n");
            return -1;
        }

        if (gn->type == GEN_DNS) {
            printf("found type GEN_DNS\n");
            printf("length = %d\n", gn->d.ia5->length);
            printf("data = %s\n", (char*)gn->d.ia5->data);
        }

        if (gn->type == GEN_EMAIL) {
            printf("found type GEN_EMAIL\n");
            printf("length = %d\n", gn->d.ia5->length);
            printf("data = %s\n", (char*)gn->d.ia5->data);
        }

        if (gn->type == GEN_URI) {
            printf("found type GEN_URI\n");
            printf("length = %d\n", gn->d.ia5->length);
            printf("data = %s\n", (char*)gn->d.ia5->data);
        }
    }
#endif
    X509_free(x509);
    sk_GENERAL_NAME_pop_free(sk, GENERAL_NAME_free);

    printf(resultFmt, passed);
#endif
}

static void test_wolfSSL_MD4(void)
{
#if defined(OPENSSL_EXTRA) && !defined(NO_MD4)
    MD4_CTX md4;
    unsigned char out[16]; /* MD4_DIGEST_SIZE */
    const char* msg  = "12345678901234567890123456789012345678901234567890123456"
                       "789012345678901234567890";
    const char* test = "\xe3\x3b\x4d\xdc\x9c\x38\xf2\x19\x9c\x3e\x7b\x16\x4f"
                       "\xcc\x05\x36";
    int msgSz        = (int)XSTRLEN(msg);

    printf(testingFmt, "wolfSSL_MD4()");

    XMEMSET(out, 0, sizeof(out));
    MD4_Init(&md4);
    MD4_Update(&md4, (const void*)msg, (unsigned long)msgSz);
    MD4_Final(out, &md4);
    AssertIntEQ(XMEMCMP(out, test, sizeof(out)), 0);

    printf(resultFmt, passed);
#endif
}


static void test_wolfSSL_RSA(void)
{
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
    RSA* rsa;

    printf(testingFmt, "wolfSSL_RSA()");

    AssertNotNull(rsa = RSA_generate_key(2048, 3, NULL, NULL));
    AssertIntEQ(RSA_size(rsa), 256);
    RSA_free(rsa);

    AssertNotNull(rsa = RSA_generate_key(3072, 17, NULL, NULL));
    AssertIntEQ(RSA_size(rsa), 384);
    RSA_free(rsa);

    AssertNotNull(rsa = RSA_generate_key(2999, 65537, NULL, NULL));
    RSA_free(rsa);

    AssertNull(RSA_generate_key(-1, 3, NULL, NULL));
    AssertNull(RSA_generate_key(511, 3, NULL, NULL)); /* RSA_MIN_SIZE - 1 */
    AssertNull(RSA_generate_key(4097, 3, NULL, NULL)); /* RSA_MAX_SIZE + 1 */
    AssertNull(RSA_generate_key(2048, 0, NULL, NULL));

    printf(resultFmt, passed);
#endif
}

static void test_wolfSSL_verify_depth(void)
{
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA)
    WOLFSSL*     ssl;
    WOLFSSL_CTX* ctx;
    long         depth;

    AssertNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));

    AssertTrue(wolfSSL_CTX_use_certificate_file(ctx, cliCert, SSL_FILETYPE_PEM));
    AssertTrue(wolfSSL_CTX_use_PrivateKey_file(ctx, cliKey, SSL_FILETYPE_PEM));
    AssertIntEQ(wolfSSL_CTX_load_verify_locations(ctx, caCert, 0), SSL_SUCCESS);

    AssertIntGT((depth = SSL_CTX_get_verify_depth(ctx)), 0);
    AssertNotNull(ssl = SSL_new(ctx));
    AssertIntEQ(SSL_get_verify_depth(ssl), SSL_CTX_get_verify_depth(ctx));
    SSL_free(ssl);

    SSL_CTX_set_verify_depth(ctx, -1);
    AssertIntEQ(depth, SSL_CTX_get_verify_depth(ctx));

    SSL_CTX_set_verify_depth(ctx, 2);
    AssertIntEQ(2, SSL_CTX_get_verify_depth(ctx));
    AssertNotNull(ssl = SSL_new(ctx));
    AssertIntEQ(2, SSL_get_verify_depth(ssl));

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    printf(resultFmt, passed);
#endif
}

static void test_no_op_functions(void)
{
    #if defined(OPENSSL_EXTRA)
    printf(testingFmt, "no_op_functions()");

    /* this makes sure wolfSSL can compile and run these no-op functions */
    SSL_load_error_strings();
    ENGINE_load_builtin_engines();
    OpenSSL_add_all_ciphers();
    CRYPTO_malloc_init();

    printf(resultFmt, passed);
    #endif
}


/*----------------------------------------------------------------------------*
 | wolfCrypt ASN
 *----------------------------------------------------------------------------*/

static void test_wc_GetPkcs8TraditionalOffset(void)
{
#if !defined(NO_ASN) && !defined(NO_FILESYSTEM)
    int length, derSz;
    word32 inOutIdx;
    const char* path = "./certs/server-keyPkcs8.der";
    FILE* file;
    byte der[2048];

    printf(testingFmt, "wc_GetPkcs8TraditionalOffset");

    file = fopen(path, "rb");
    AssertNotNull(file);
    derSz = (int)fread(der, 1, sizeof(der), file);
    fclose(file);

    /* valid case */
    inOutIdx = 0;
    length = wc_GetPkcs8TraditionalOffset(der, &inOutIdx, derSz);
    AssertIntGT(length, 0);

    /* inOutIdx > sz */
    inOutIdx = 4000;
    length = wc_GetPkcs8TraditionalOffset(der, &inOutIdx, derSz);
    AssertIntEQ(length, BAD_FUNC_ARG);

    /* null input */
    inOutIdx = 0;
    length = wc_GetPkcs8TraditionalOffset(NULL, &inOutIdx, 0);
    AssertIntEQ(length, BAD_FUNC_ARG);

    /* invalid input, fill buffer with 1's */
    XMEMSET(der, 1, sizeof(der));
    inOutIdx = 0;
    length = wc_GetPkcs8TraditionalOffset(der, &inOutIdx, derSz);
    AssertIntEQ(length, ASN_PARSE_E);

    printf(resultFmt, passed);
#endif /* NO_ASN */
}


/*----------------------------------------------------------------------------*
 | Main
 *----------------------------------------------------------------------------*/

void ApiTest(void)
{
    printf(" Begin API Tests\n");
    AssertIntEQ(test_wolfSSL_Init(), SSL_SUCCESS);
    /* wolfcrypt initialization tests */
    AssertFalse(test_wolfCrypt_Init());
    test_wolfSSL_Method_Allocators();
    test_wolfSSL_CTX_new(wolfSSLv23_server_method());
    test_wolfSSL_CTX_use_certificate_file();
    AssertIntEQ(test_wolfSSL_CTX_use_certificate_buffer(), SSL_SUCCESS);
    test_wolfSSL_CTX_use_PrivateKey_file();
    test_wolfSSL_CTX_load_verify_locations();
    test_wolfSSL_CTX_trust_peer_cert();
    test_wolfSSL_CTX_SetTmpDH_file();
    test_wolfSSL_CTX_SetTmpDH_buffer();
    test_server_wolfSSL_new();
    test_client_wolfSSL_new();
    test_wolfSSL_SetTmpDH_file();
    test_wolfSSL_SetTmpDH_buffer();
    test_wolfSSL_read_write();
    test_wolfSSL_dtls_export();
    AssertIntEQ(test_wolfSSL_SetMinVersion(), SSL_SUCCESS);
    AssertIntEQ(test_wolfSSL_CTX_SetMinVersion(), SSL_SUCCESS);

    /* TLS extensions tests */
    test_wolfSSL_UseSNI();
    test_wolfSSL_UseMaxFragment();
    test_wolfSSL_UseTruncatedHMAC();
    test_wolfSSL_UseSupportedCurve();
    test_wolfSSL_UseALPN();
    test_wolfSSL_DisableExtendedMasterSecret();

    /* X509 tests */
    test_wolfSSL_X509_NAME_get_entry();
    test_wolfSSL_PKCS12();

    /*OCSP Stapling. */
    AssertIntEQ(test_wolfSSL_UseOCSPStapling(), SSL_SUCCESS);
    AssertIntEQ(test_wolfSSL_UseOCSPStaplingV2(), SSL_SUCCESS);

    /* compatibility tests */
    test_wolfSSL_X509_NAME();
    test_wolfSSL_DES();
    test_wolfSSL_certs();
    test_wolfSSL_private_keys();
    test_wolfSSL_PEM_PrivateKey();
    test_wolfSSL_tmp_dh();
    test_wolfSSL_ctrl();
    test_wolfSSL_CTX_add_extra_chain_cert();
    test_wolfSSL_ERR_peek_last_error_line();
    test_wolfSSL_X509_STORE_set_flags();
    test_wolfSSL_BN();
    test_wolfSSL_set_options();
    test_wolfSSL_PEM_read_bio();
    test_wolfSSL_BIO();
    test_wolfSSL_ASN1_STRING();
    test_wolfSSL_X509();
    test_wolfSSL_RAND();
    test_wolfSSL_BUF();
    test_wolfSSL_pseudo_rand();
    test_wolfSSL_pkcs8();
    test_wolfSSL_ERR_put_error();
    test_wolfSSL_HMAC();
    test_wolfSSL_OBJ();
    test_wolfSSL_X509_NAME_ENTRY();
    test_wolfSSL_BIO_gets();
    test_wolfSSL_BIO_write();
    test_wolfSSL_SESSION();
    test_wolfSSL_sk_GENERAL_NAME();
    test_wolfSSL_MD4();
    test_wolfSSL_RSA();
    test_wolfSSL_verify_depth();

    /* test the no op functions for compatibility */
    test_no_op_functions();

    AssertIntEQ(test_wolfSSL_Cleanup(), SSL_SUCCESS);

    /* wolfCrypt ASN tests */
    test_wc_GetPkcs8TraditionalOffset();

    printf(" End API Tests\n");

}
