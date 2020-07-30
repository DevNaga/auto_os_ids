#ifndef __AUTO_OS_TYPES_H__
#define __AUTO_OS_TYPES_H__

#define AUTO_OS_MACADDR_LEN 6

#ifdef CONFIG_COMPILER_GCC
#define pack_struct __attribute__((__packed__))
#endif

#endif

