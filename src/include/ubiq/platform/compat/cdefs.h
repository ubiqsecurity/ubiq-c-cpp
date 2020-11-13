#pragma once

#if defined(_WIN32)
#  if defined(__cplusplus)
#    define __BEGIN_DECLS               extern "C" {
#    define __END_DECLS                 }
#  else
#    define __BEGIN_DECLS
#    define __END_DECLS
#  endif

#  if defined(STATIC_IMPORT)
#    define UBIQ_PLATFORM_API
#  else
#    if defined(DLL_EXPORT)
#      define UBIQ_PLATFORM_API           __declspec(dllexport)
#    else
#      define UBIQ_PLATFORM_API           __declspec(dllimport)
#    endif
#  endif
#else
#  include <sys/cdefs.h>

#  define UBIQ_PLATFORM_API
#endif
