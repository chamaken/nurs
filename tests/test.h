#ifndef _NURS_TEST_H
#define _NURS_TEST_H

#include <assert.h>

#define __visible	__attribute__((visibility("default")))
#define EXPORT(x)	typeof(x) (x) __visible

#define assertf(a, format, args...) do {	 \
  fprintf(stdout, "[[ " format " ]]\n", ##args); \
  fflush(stdout);				 \
  assert((a)); } while (0)

#endif /* _NURS_TEST_H */
