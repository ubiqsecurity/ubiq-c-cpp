#include "ubiq/platform.h"

#include <thread>
#include <chrono>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <gtest/gtest.h>

class UbiqPlatformLibraryEnvironment :
    public ::testing::Environment
{
public:
    virtual void SetUp(void) override
        {
            ubiq::platform::init();
        }
    virtual void TearDown(void) override
        {
            ubiq::platform::exit();
        }
};
/*
 * add environments by declaring them below this line
 * googletest takes ownership of the pointers; do NOT free them.
 */

static ::testing::Environment * const vle =
    ::testing::AddGlobalTestEnvironment(
        new UbiqPlatformLibraryEnvironment);
