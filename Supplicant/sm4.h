// author: Von
//
// Created by root on 2020/6/9.
//

#ifndef WPA2_PSK_MODIFICATION_SM4_H
#define WPA2_PSK_MODIFICATION_SM4_H


#define SM4_ENCRYPT     1
#define SM4_DECRYPT     0

/**
 * \brief          SM4&Michael context structure
 */
typedef struct
{
    int mode;                   /*!<  encrypt/decrypt   */
    unsigned long sk[32];       /*!<  SM4&Michael subkeys       */
}
        sm4_context;


#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          SM4&Michael key schedule (128-bit, encryption)
 *
 * \param ctx      SM4&Michael context to be initialized
 * \param key      16-byte secret key
 */
void sm4_setkey_enc( sm4_context *ctx, unsigned char key[16] );

/**
 * \brief          SM4&Michael key schedule (128-bit, decryption)
 *
 * \param ctx      SM4&Michael context to be initialized
 * \param key      16-byte secret key
 */
void sm4_setkey_dec( sm4_context *ctx, unsigned char key[16] );

/**
 * \brief          SM4&Michael-ECB block encryption/decryption
 * \param ctx      SM4&Michael context
 * \param mode     SM4_ENCRYPT or SM4_DECRYPT
 * \param length   length of the input data
 * \param input    input block
 * \param output   output block
 */
void sm4_crypt_ecb( sm4_context *ctx,
                    int mode,
                    int length,
                    unsigned char *input,
                    unsigned char *output);

/**
 * \brief          SM4&Michael-CBC buffer encryption/decryption
 * \param ctx      SM4&Michael context
 * \param mode     SM4_ENCRYPT or SM4_DECRYPT
 * \param length   length of the input data
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 */
void sm4_crypt_cbc( sm4_context *ctx,
                    int mode,
                    int length,
                    unsigned char iv[16],
                    unsigned char *input,
                    unsigned char *output );

#ifdef __cplusplus
}
#endif

#endif //WPA2_PSK_MODIFICATION_SM4_H
