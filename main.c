#if defined (CY_USING_HAL)
#include "cyhal.h"
#endif
#include "cybsp.h"
#include "cy_retarget_io.h"
#include "ecp.h"
#include "ecdh.h"
#include "entropy.h"
#include "ctr_drbg.h"
#include "ecdsa.h"
#include "sha256.h"
/******************************************************************************
* Macros
*******************************************************************************/

#define Sizelength 32
/*******************************************************************************
* Global Variables
*******************************************************************************/


/*******************************************************************************
* Function Prototypes
*******************************************************************************/


/*******************************************************************************
* Function Definitions
*******************************************************************************/
/*******************************************************************************
* Function Name: print_data()
********************************************************************************
* Summary:
* 	Function used to display the data in hexadecimal format
*
* Parameters:
*  uint8_t* data - Pointer to location of data to be printed
*  size_t  len  - length of data to be printed
*
* Return:
*  void
*
*******************************************************************************/
void print_uint8_data(uint8_t* data, size_t len)
{
    char print[10];
    for (uint8_t i=0; i < len; i++)
    {
        if ((i % 16) == 0)
        {
            printf("\r\n");
        }
        sprintf(print,"0x%02X ", *(data+i));
        printf("%s", print);
    }
    printf("\r\n");
}

/*******************************************************************************
 * Function Name: print_mpi_data()
 ********************************************************************************
 * Summary:
 *  Prints the contents of an mbedtls_mpi structure in hexadecimal format.
 *
 * Parameters:
 *  mbedtls_mpi* data: Pointer to the mbedtls_mpi structure to be printed.
 *  size_t  len  - length of data to be printed
 *
 * Return:
 *  void
 *
 *******************************************************************************/
void print_mpi_data(mbedtls_mpi* data)
{
	size_t len = mbedtls_mpi_size(data);
	unsigned char buffer[100] = {0};
    mbedtls_mpi_write_binary(data, buffer, len);
    print_uint8_data(buffer, len);
}

/*******************************************************************************
 * Function Name: print_ecp_point_data()
 ********************************************************************************
 * Summary:
 *  Prints the contents of an mbedtls_ecp_point structure in
 *  uncompressed binary format.
 *
 * Parameters:
 *  mbedtls_ecp_point* data: Pointer to the mbedtls_ecp_point structure to be printed.
 *  mbedtls_ecp_group* grp: Pointer to the mbedtls_ecp_group structure associated
 *  with the point.
 *
 * Return:
 *  void
 *
 ******************************************************************************/
void print_ecp_point_data(mbedtls_ecp_point* data, mbedtls_ecp_group *grp)
{
	unsigned char buffer[100] = {0};
	size_t buflen = 0; //ECP_KEY_LENGTH

    mbedtls_ecp_point_write_binary(grp, data, MBEDTLS_ECP_PF_UNCOMPRESSED,
    		&buflen, buffer, sizeof(buffer));
    print_uint8_data(buffer, buflen);
}

/*******************************************************************************
* Function Name: main
*********************************************************************************
* Summary:
* This is the main function for CPU. It...
*    1.
*    2.
*
* Parameters:
*  void
*
* Return:
*  int
*
*******************************************************************************/
int main(void)
{
    cy_rslt_t result;

    /* Initialize the device and board peripherals */
    result = cybsp_init();

    /* Board init failed. Stop program execution */
    if (result != CY_RSLT_SUCCESS)
    {
        CY_ASSERT(0);
    }

    /* Enable global interrupts */
    __enable_irq();

    /* Initialize retarget-io to use the debug UART port */
    result = cy_retarget_io_init(CYBSP_DEBUG_UART_TX, CYBSP_DEBUG_UART_RX,
    		CY_RETARGET_IO_BAUDRATE);

    /* UART port init failed. Stop program execution */
	if (result != CY_RSLT_SUCCESS)
	{
	   CY_ASSERT(0);
	}

    /* \x1b[2J\x1b[;H - ANSI ESC sequence for clear screen */
    printf("\x1b[2J\x1b[;H");

	printf("PSOC_OPTIGA_IOT_KIT template is ready to start.\r\n");


	 mbedtls_ctr_drbg_context ctr_drbg;

		 	mbedtls_ctr_drbg_init(&ctr_drbg);

		 	const char *pers = "varun_kumar";
		 	mbedtls_entropy_context entropy;
		 	mbedtls_entropy_init(&entropy);

		 	mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,(const uint8_t *)pers, strlen(pers));



	mbedtls_ecdsa_context ecdsa_alice;
	mbedtls_ecdsa_init(&ecdsa_alice);

	mbedtls_ecdsa_context ecdsa_bob;
	mbedtls_ecdsa_init(&ecdsa_bob);

	mbedtls_ecdsa_genkey(&ecdsa_alice, MBEDTLS_ECP_DP_SECP256R1, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ecdsa_genkey(&ecdsa_bob, MBEDTLS_ECP_DP_SECP256R1, mbedtls_ctr_drbg_random, &ctr_drbg);

	unsigned char input[Sizelength];
	unsigned char output2[Sizelength];


	mbedtls_sha256_context sha256;
	mbedtls_sha256_init(&sha256);
	mbedtls_sha256_starts_ret(&sha256, 0);
	mbedtls_sha256_update_ret(&sha256, input, 32);
	mbedtls_sha256_finish_ret(&sha256, hash);
	//unsigned char hash[Sizelength];
	unsigned char sig[73];
	unsigned char md[Sizelength];
	mbedtls_ecdsa_write_signature(&ecdsa_alice, MBEDTLS_MD_SHA256, hash, sizeof(hash), sig, sizeof(sig), mbedtls_ctr_drbg_random, &ctr_drbg);

	mbedtls_ecp_group_copy(&ecdsa_alice.grp, &ecdsa_bob.grp);
	mbedtls_ecp_copy(&ecdsa_alice.Q,&ecdsa_bob.Q);
	mbedtls_ecdsa_read_signature(&ecdsa_bob, output2, sizeof(hash), sig, Sizelength);

	if(mbedtls_ecdsa_read_signature==0)
	{
		printf("Crazyyy");
	}
	else
	{
		printf("So sad");
	}





}
