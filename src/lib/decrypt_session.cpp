#include "ubiq/platform/decrypt.h"

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


 decryption_session::decryption_session(decryption &decryption)
{
    UBIQ_DEBUG(debug_flag, printf("decryption_session constructor(decryption &decryption)\n"));
    struct ubiq_platform_decryption_session * session;
    int res(0);

    res = ubiq_platform_decryption_init_session(decryption._dec.get(), &session);
    UBIQ_DEBUG(debug_flag, printf("decryption_session constructor(&decryption) res(%d) session(%p)\n", res, session));
    if (res != 0) {
        throw std::system_error(-res, std::generic_category(), "in decryption_session during ubiq_platform_decryption_init_session");
    }

    _session.reset(session, &ubiq_platform_decryption_destroy_session);
}

 decryption_session::decryption_session()
{
    struct ubiq_platform_decryption_session * session = nullptr;
    UBIQ_DEBUG(debug_flag, printf("decryption_session() constructor\n"));

    _session.reset(session, &ubiq_platform_decryption_destroy_session);
}



