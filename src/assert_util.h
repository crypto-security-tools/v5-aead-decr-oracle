#ifndef _ASSERT_H
#define _ASSERT_H

#include <cassert>

#define assertm(exp, msg) assert(((void)msg, exp))


#endif /* _ASSERT_H */
