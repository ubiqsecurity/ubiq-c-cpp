#include <ubiq/platform/internal/support.h>

int
ubiq_support_base64_encode(
    char ** const _str,
    const void * const buf, const size_t len)
{
    char * str;
    int res;
    DWORD out;

    out = 0;
    CryptBinaryToStringA(buf, len,
                         CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                         NULL, &out);
    out++;

    res = -ENOMEM;
    str = malloc(out);
    if (str) {
        CryptBinaryToStringA(buf, len,
                             CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                             str, &out);
        *_str = str;
        res = 0;
    }

    return res;
}

int
ubiq_support_base64_decode(
    void ** const _buf,
    const char * const str, const size_t len)
{
    void * buf;
    int res;
    DWORD out;

    out = 0;
    CryptStringToBinaryA(str, len,
                         CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT,
                         NULL, &out,
                         NULL, NULL);

    res = -ENOMEM;
    buf = malloc(out);
    if (buf) {
        CryptStringToBinaryA(str, len,
                             CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT,
                             buf, &out,
                             NULL, NULL);
        *_buf = buf;
        res = 0;
    }

    return res;
}
