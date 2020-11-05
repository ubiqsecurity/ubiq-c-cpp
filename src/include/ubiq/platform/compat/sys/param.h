#pragma once

#if defined(_WIN32)
#  define MIN(A, B)                     (((A) < (B)) ? (A) : (B))
#else
#  include <sys/param.h>
#endif
