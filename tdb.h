
#ifndef _TDB_H
#define _TDB_H

union u_data {
  unsigned long val;
  char bytes[sizeof(unsigned long)];
};

#ifdef __USE_SOFTWARE_BP
struct tdb_breakpoint {
  long address_mask[0x1000 / sizeof(unsigned long)];
};
#endif
#ifdef __USE_HARDWARE_BP
struct tdb_breakpoint {
  int valid;
  int backupcode_size;
  union u_data backupcode;
  unsigned long address;
};
#endif

#endif

