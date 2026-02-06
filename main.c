/*******************************************************************************

* File Name:   main.c

*

* Description:

*  ECDSA sign and verify example using mbedTLS on PSoC (ModusToolbox)

*

*******************************************************************************/



#include <stdio.h>

#include <string.h>



#if defined (CY_USING_HAL)

#include "cyhal.h"

#endif



#include "cybsp.h"

#include "cy_retarget_io.h"



/* mbedTLS headers */

#include "entropy.h"

#include "ctr_drbg.h"

#include "sha256.h"

#include "ecdsa.h"

#include "ecp.h"



/*******************************************************************************

* Helper Functions

*******************************************************************************/

void print_uint8_data(uint8_t* data, size_t len)

{

    for (size_t i = 0; i < len; i++)

    {

        if ((i % 16) == 0)

            printf("\r\n");



        printf("0x%02X ", data[i]);

    }

    printf("\r\n");

}



/*******************************************************************************

* Main Function

*******************************************************************************/

int main(void)

{

    cy_rslt_t result;



    /* Initialize board */

    result = cybsp_init();

    if (result != CY_RSLT_SUCCESS)

    {

        CY_ASSERT(0);

    }



    __enable_irq();



    /* Initialize UART */

    result = cy_retarget_io_init(CYBSP_DEBUG_UART_TX,

                                 CYBSP_DEBUG_UART_RX,

                                 CY_RETARGET_IO_BAUDRATE);

    if (result != CY_RSLT_SUCCESS)

    {

        CY_ASSERT(0);

    }



    printf("\x1b[2J\x1b[;H");

    printf("ECDSA Sign & Verify Example\r\n");



    /* RNG setup */

    mbedtls_entropy_context entropy;

    mbedtls_ctr_drbg_context ctr_drbg;



    mbedtls_entropy_init(&entropy);

    mbedtls_ctr_drbg_init(&ctr_drbg);



    const char *pers = "psoc_ecdsa_example";



    mbedtls_ctr_drbg_seed(&ctr_drbg,

                              mbedtls_entropy_func,

                              &entropy,

                              (const uint8_t *)pers,

                              strlen(pers));



    /* Contexts */

    mbedtls_ecdsa_context Alice;

    mbedtls_ecdsa_context Bob;

    mbedtls_sha256_context sha_ctx;



    mbedtls_ecdsa_init(&Alice);

    mbedtls_ecdsa_init(&Bob);

    mbedtls_sha256_init(&sha_ctx);



    /* Generate ECDSA keys */

    mbedtls_ecdsa_genkey(&Alice,

                         MBEDTLS_ECP_DP_SECP256R1,

                         mbedtls_ctr_drbg_random,

                         &ctr_drbg);



    /* Bob gets same public key (verification side) */

    mbedtls_ecp_group_copy(&Bob.grp, &Alice.grp);
    mbedtls_ecp_copy(&Bob.Q, &Alice.Q);


    printf("ECDSA key generated\r\n");


    /* Input message */

    const unsigned char input_data[16] = "HELLO_PSoC_123";
    unsigned char hash[32];



    /* SHA256 hash */

    mbedtls_sha256_starts_ret(&sha_ctx, 0);
    mbedtls_sha256_update_ret(&sha_ctx, input_data, 16);
    mbedtls_sha256_finish_ret(&sha_ctx, hash);



    printf("SHA256 Hash:");
    print_uint8_data(hash, 32);


    /* ECDSA signature */

    unsigned char signature[73];

    size_t sig_len;

    mbedtls_ecdsa_write_signature(&Alice,  MBEDTLS_MD_SHA256,  hash, 32, signature, &sig_len, mbedtls_ctr_drbg_random,&ctr_drbg);


    printf("Signature:");
    print_uint8_data(signature, sig_len);

    /* Verify signature */

    int verify_status = mbedtls_ecdsa_read_signature(&Bob, hash, 32,  signature,   sig_len);

    if (verify_status == 0)
    {
        printf("\r\nSignature VERIFIED SUCCESSFULLY\r\n");
    }
    else
    {
        printf("\r\nSignature VERIFICATION FAILED \r\n");
    }

    /* Free contexts */

    mbedtls_ecdsa_free(&Alice);
    mbedtls_ecdsa_free(&Bob);
    mbedtls_sha256_free(&sha_ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);



}
