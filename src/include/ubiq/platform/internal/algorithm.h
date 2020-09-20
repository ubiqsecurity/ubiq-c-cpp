#pragma once

#include <openssl/evp.h>

const uint8_t UBIQ_AES_AAD_FLAG;

void ubiq_platform_algorithm_init(void);
void ubiq_platform_algorithm_exit(void);

struct ubiq_platform_algorithm
{
    unsigned int id;
    const EVP_CIPHER * cipher;
    /* key, block, iv, etc. sizes are known by the cihper */
    unsigned int taglen;
};

const struct ubiq_platform_algorithm *
ubiq_platform_algorithm_get_byid(
    unsigned int);
const struct ubiq_platform_algorithm *
ubiq_platform_algorithm_get_bycipher(
    const EVP_CIPHER *);
