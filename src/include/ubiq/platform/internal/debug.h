#ifndef UBIQ_STRUCTURED_DEBUG_H
#define UBIQ_STRUCTURED_DEBUG_H

// #define STRUCTURED_DEBUG_ON // UNCOMMENT to Enable STRUCTURED_DEBUG macro

#ifdef STRUCTURED_DEBUG_ON
#define STRUCTURED_DEBUG(x,y) {x && y;}
#else
#define STRUCTURED_DEBUG(x,y)
#endif


#endif