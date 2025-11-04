#include "ubiq/platform/encrypt.h"

#include <system_error>
#include <cstring>

using namespace ubiq::platform;

// #define UBIQ_DEBUG_ON
#ifdef UBIQ_DEBUG_ON
#define UBIQ_DEBUG(x,y) {x && y;}
#else
#define UBIQ_DEBUG(x,y)
#endif

static int debug_flag = 0;


 encryption_session::encryption_session(encryption &encryption)
{
    UBIQ_DEBUG(debug_flag,printf("encryption_session constructor(encryption &encryption)\n"));
    struct ubiq_platform_encryption_session * session;
    int res(0);

    res = ubiq_platform_encryption_init_session(encryption._enc.get(), &session);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category(), "in encryption_session during ubiq_platform_encryption_init_session");
    }

    _session.reset(session, &ubiq_platform_encryption_destroy_session);
}

 encryption_session::encryption_session()
{
    struct ubiq_platform_encryption_session * session = nullptr;
    UBIQ_DEBUG(debug_flag,printf("encryption_session() constructor\n"));

    _session.reset(session, &ubiq_platform_encryption_destroy_session);
}



