
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/user.h>

#include <signal.h>
#include <unistd.h>
#include <libdis.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <error.h>

//#define __USE_SOFTWARE_BP
#define __USE_HARDWARE_BP

#include "tdb.h"

#define DEBUGGER_BANNER  "tdb"
#define CMDLINE_LEN      256

#define TDBG_CONTINUE     1
#define TDBG_STEP         2
#define TDBG_DONOTHING    3
#define TDBG_EXIT         -1

static const char *delim = " ";

#ifdef __USE_SOFTWARE_BP
void set_tdbp_bit(unsigned long address, struct tdb_breakpoint *bp_table);
void clear_tdbp_bit(unsigned long address, struct tdb_breakpoint *bp_table);
int check_tdbp_bit(unsigned long address, struct tdb_breakpoint *bp_table);

int set_break_point(unsigned long address);
int clear_break_point(unsigned long address);
int check_break_point(unsigned long address);

void print_address_mask(unsigned long bptable_num,
						struct tdb_breakpoint *bp);

void enum_bp_list(void);
void init_bptable(void);
void free_all_bptable(void);
#endif

#ifdef __USE_HARDWARE_BP
int set_break_point(pid_t child, unsigned long address);
void clear_break_point(pid_t child, int bp_num);
struct tdb_breakpoint *check_break_point(unsigned long address);

void enum_bp_list(void);
void init_bptable(pid_t child);
void free_all_bptable(pid_t child);
#endif

void readdata(pid_t child, unsigned long addr, char *str, int len);
void writedata(pid_t child, unsigned long addr, char *str, int len);

int dump_debug(pid_t child, int status, struct user_regs_struct *regs, char **tkptr);
int exit_debug(pid_t child, int status, struct user_regs_struct *regs, char **tkptr);
int step_debug(pid_t child, int status, struct user_regs_struct *regs, char **tkptr);
int cont_debug(pid_t child, int status, struct user_regs_struct *regs, char **tkptr);
int show_help(pid_t child, int status, struct user_regs_struct *regs, char **tkptr);
int break_point(pid_t child, int status, struct user_regs_struct *regs, char **tkptr);
int enum_bp(pid_t child, int status, struct user_regs_struct *regs, char **tkptr);
int disasm_range(pid_t child, int status, struct user_regs_struct *regs, char **tkptr);

struct tdb_commands {
  char *command_name;
  char *alias;
  char *guide;
  int (*func)(pid_t, int, struct user_regs_struct*, char**);
} cmd_resources[] = {
  {"c",
   "continue",
   "Continue executing until next break point/watchpoint.",
   cont_debug
  },  
  {"s",
   "step",
   "Step to next line of code. Will step into a function.",
   step_debug
  },  
  {"r",
   "register",
   "List registers in use.",
   dump_debug
  },  
  {"h",
   "help",
   "List tdb command topics.",
   show_help
  },  
  {"q",
   "quit",
   "Exit tdb debugger.",
   exit_debug
  },
  {"b",
   "break",
   "Making program stop at certain points.",
   break_point
  },
  {"l",
   "listbp",
   "List breakpoints in valid.",
   enum_bp
  },
  {"d",
   "disasm",
   "Disassemble a specified section of memory.",
   disasm_range
  }
};

static int numofcmd =
  sizeof(cmd_resources) / sizeof(struct tdb_commands);

static const int long_size = sizeof(unsigned long);

#define DUMP_GENREG(name, val) \
  printf("%s 0x%08lx %15ld\n", #name, (val), (val));

#define DUMP_SEGREG(name, val) \
  printf("%s 0x%04x %15d\n", #name, (val), (val));

int dump_debug(pid_t child, int status, struct user_regs_struct *regs, char **tkptr)
{
  DUMP_GENREG(eax, regs->eax); DUMP_GENREG(ecx, regs->ecx);
  DUMP_GENREG(edx, regs->edx); DUMP_GENREG(ebp, regs->ebx);
  DUMP_GENREG(esp, regs->esp); DUMP_GENREG(ebp, regs->ebp);
  DUMP_GENREG(esi, regs->esi); DUMP_GENREG(edi, regs->edi);

  printf("eip 0x%04lx 0x%04lx <>\n", regs->eip, regs->eip);
  printf("eflags 0x%lx\n", regs->eflags);

  DUMP_SEGREG(cs, regs->cs); DUMP_SEGREG(ss, regs->ss);
  DUMP_SEGREG(ds, regs->ds); DUMP_SEGREG(es, regs->es);
  DUMP_SEGREG(fs, regs->fs); DUMP_SEGREG(gs, regs->gs);
  
  return TDBG_DONOTHING;
}

int exit_debug(pid_t child, int status, struct user_regs_struct *regs, char **tkptr)
{
  return TDBG_EXIT;
}

int step_debug(pid_t child, int status, struct user_regs_struct *regs, char **tkptr)
{
  return TDBG_STEP;
}

int cont_debug(pid_t child, int status, struct user_regs_struct *regs, char **tkptr)
{
  return TDBG_CONTINUE;
}

int show_help(pid_t child, int status, struct user_regs_struct *regs, char **tkptr)
{
  int i;

  for (i = 0 ; i < numofcmd ; i++) {
	printf(" %s %s -- %s\n",
		   cmd_resources[i].command_name,
		   cmd_resources[i].alias,
		   cmd_resources[i].guide);
  }

  return TDBG_DONOTHING;  
}

int break_point(pid_t child, int status, struct user_regs_struct *regs, char **tkptr)
{
  char *tp = strtok_r(NULL, delim, tkptr);
  
  int radix = 10;
  unsigned long bp_address;

  if (tp == NULL) {
	goto error;
  }

  if (strlen(tp) > 2) {
	if (tp[0] == '0' && tp[1] == 'x') {
	  radix = 16;
	  tp += 2;
	}
  }

  bp_address = strtoul(tp, NULL, radix);
  //  if (errno == ERANGE) {
  //	goto error;
  //  }

#ifdef __USE_SOFTWARE_BP
  set_break_point(bp_address);
#endif

#ifdef __USE_HARDWARE_BP
  set_break_point(child, bp_address);
#endif

  return TDBG_DONOTHING;
  
 error:
  printf("invalid address\n");
  return TDBG_DONOTHING;
}

int enum_bp(pid_t child, int status, struct user_regs_struct *regs, char **tkptr)
{
  enum_bp_list();
  return TDBG_DONOTHING;
}

int disasm_range(pid_t child, int status, struct user_regs_struct *regs, char **tkptr)
{
}

#ifdef __USE_SOFTWARE_BP

#define BPTABLE_SHIFT   12
#define BPTABLE_SIZE    (1UL << BPTABLE_SHIFT)
#define BPTABLE_MASK    (~(BPTABLE_SIZE - 1))

#define BPTABLE_PDE(x)  ((x) >> 22)
#define BPTABLE_PTE(x)  (((x) >> 12) & 0x3ff)
#define PAGE_NUM(pde, pte)  (((pde) << 22) | ((pte) << 12))

static int enable_bp = 0;
static struct tdb_breakpoint *tdb_bp_table[1024] = { NULL };
static const int bpte_of_num = sizeof(tdb_bp_table) / sizeof(struct tdb_breakpoint*);

void set_tdbp_bit(unsigned long address, struct tdb_breakpoint *bp_table)
{
  unsigned long val = 1 << (address % sizeof(unsigned long));
  bp_table->address_mask[(address & ~BPTABLE_MASK) / sizeof(unsigned long)] |= val;
}

void clear_tdbp_bit(unsigned long address, struct tdb_breakpoint *bp_table)
{
  unsigned long val = 1 << (address % sizeof(unsigned long));
  bp_table->address_mask[(address & ~BPTABLE_MASK) / sizeof(unsigned long)] &= ~val;
}

int check_tdbp_bit(unsigned long address, struct tdb_breakpoint *bp_table)
{
  unsigned long val = 1 << (address % sizeof(unsigned long));
  return bp_table->address_mask[(address & ~BPTABLE_MASK) / sizeof(unsigned long)] & val;
}

int set_break_point(unsigned long address)
{
  struct tdb_breakpoint *bp = tdb_bp_table[BPTABLE_PDE(address)];

  enable_bp = 1;
  
  if (bp == NULL) {
	tdb_bp_table[BPTABLE_PDE(address)] = malloc(sizeof(struct tdb_breakpoint) * 1024);
	bp = tdb_bp_table[BPTABLE_PDE(address)];
	memset(bp, 0, sizeof(struct tdb_breakpoint) * 1024);
  }

  set_tdbp_bit(address, &bp[BPTABLE_PTE(address)]);

  return 1;
}

int clear_break_point(unsigned long address)
{
  struct tdb_breakpoint *bp = tdb_bp_table[BPTABLE_PDE(address)];
  
  if (bp == NULL) {
	return 0;
  } else {
	clear_tdbp_bit(address, &bp[BPTABLE_PTE(address)]);
  }
  
  return 1;
}

int check_break_point(unsigned long address)
{
  struct tdb_breakpoint *bp = tdb_bp_table[BPTABLE_PDE(address)];
  if (bp == NULL) {
	return 0;
  }
  return check_tdbp_bit(address, &bp[BPTABLE_PTE(address)]);
}

void print_address_mask(unsigned long bptable_num,
						struct tdb_breakpoint *bp)
{
  int i, j;
  unsigned long bp_address, mask;
  
  for (i = 0 ; i < (0x1000 / sizeof(unsigned long)) ; i++) {	
	if (bp->address_mask[i]) {
	  mask = bp->address_mask[i];	  
	  for (j = 0 ; j < (sizeof(unsigned long) * 8) ; j++) {		
		if ((mask >> j) & 1) {
		  bp_address = bptable_num | (sizeof(unsigned long) * i + j);
		  printf(" 0x%08lx\n", bp_address);
		}
	  }
	}
  }
}

void enum_bp_list(void)
{
  int i = 0;
  for ( ; i < bpte_of_num ; i++ ) {
	if (tdb_bp_table[i] != NULL) {	  
	  struct tdb_breakpoint *bp = tdb_bp_table[i];
	  int j = 0;	  
	  for ( ; j < 1024 ; j++ ) {
		print_address_mask(PAGE_NUM(i, j), &bp[j]);
	  }
	}
  }
}

void init_bptable(void)
{
  int i = 0;

  for ( ; i < bpte_of_num ; i++ ) {
	if (tdb_bp_table[i] != NULL) {
	  free(tdb_bp_table[i]);
	} else {
	  tdb_bp_table[i] = NULL;
	}
  }

  return;
}

void free_all_bptable(void)
{
  int i = 0;

  for ( ; i < bpte_of_num ; i++ ) {
	if (tdb_bp_table[i] != NULL) {
	  free(tdb_bp_table[i]);
	}
  }

  return;
}
#endif
#ifdef __USE_HARDWARE_BP
static struct tdb_breakpoint tdb_bp_table[1024];
static const int bpte_of_num = sizeof(tdb_bp_table) / sizeof(struct tdb_breakpoint);
static int enable_bp = 0;

/* int3 */
static char dbg_code[] = {0xcc};

int inject_int3(pid_t child, unsigned long addr,
				char *backup_code, int backupcode_size)
{

  readdata(child, addr, backup_code, backupcode_size);
  writedata(child, addr, dbg_code, sizeof(dbg_code));
  
  return 1;
}

int set_break_point(pid_t child, unsigned long address)
{
  int i;

  enable_bp = 1;
  
  for (i = 0 ; i < bpte_of_num ; i++) {
	if (tdb_bp_table[i].valid == -1) {
	  tdb_bp_table[i].valid = 1;
	  tdb_bp_table[i].address = address;
	  tdb_bp_table[i].backupcode.val = 0;
	  tdb_bp_table[i].backupcode_size = sizeof(dbg_code);
	  
	  inject_int3(child, address,
				  tdb_bp_table[i].backupcode.bytes,
				  tdb_bp_table[i].backupcode_size);

	  printf("Setting break point 0x%08lx -- 0x%08lx\n",
			 tdb_bp_table[i].address,
			 tdb_bp_table[i].backupcode.val);
	  
	  return i;
	}
  }
  return -1;
}

void clear_break_point(pid_t child, int bp_num)
{
  if (tdb_bp_table[bp_num].valid > 0) {
	writedata(child,
			  tdb_bp_table[bp_num].address,
			  tdb_bp_table[bp_num].backupcode.bytes,
			  tdb_bp_table[bp_num].backupcode_size);
	tdb_bp_table[bp_num].valid = -1;
  }
}

struct tdb_breakpoint *check_break_point(unsigned long address)
{
  int i;
  
  for (i = 0 ; i < bpte_of_num ; i++) {
	if (tdb_bp_table[i].valid > 0 &&
		tdb_bp_table[i].address == address) {
	  return &tdb_bp_table[i];
	}
  }

  return NULL;
}

void enum_bp_list(void)
{
  int i;
  for (i = 0 ; i < bpte_of_num ; i++) {
	if (tdb_bp_table[i].valid > 0) {
	  printf(" [%d] -- 0x%08lx\n", i, tdb_bp_table[i].address);
	}
  }
}

void init_bptable(pid_t child)
{
  int i;
  for (i = 0 ; i < bpte_of_num ; i++ ) {
	if (tdb_bp_table[i].valid > 0) {
	  writedata(child,
				tdb_bp_table[i].address,
				tdb_bp_table[i].backupcode.bytes,
				tdb_bp_table[i].backupcode_size);
	}
	tdb_bp_table[i].valid = -1;
  }
  
  enable_bp = 0;
  
  return;
}

void free_all_bptable(pid_t child)
{
  enable_bp = 0;
}

void restore_breakpoint(pid_t child, int bp_num)
{

  if (bp_num < 0) {
	return;
  }
  
  if (tdb_bp_table[bp_num].valid > 0) {
	inject_int3(child, tdb_bp_table[bp_num].address,
				tdb_bp_table[bp_num].backupcode.bytes,
				tdb_bp_table[bp_num].backupcode_size);
  }
}

void restore_inst(pid_t child, struct tdb_breakpoint *bp)
{
  writedata(child, bp->address, bp->backupcode.bytes,
			bp->backupcode_size);
}
#endif

void readdata(pid_t child, unsigned long addr, char *str, int len)
{
  int i = 0;
  int j = len / long_size;
  char *laddr = str;
  union u_data data;

  while (i < j) {
	data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 4, NULL);
	memcpy(laddr, data.bytes, long_size);
	++i;
	laddr += long_size;
  }

  j = len % long_size;
  if (j != 0) {
	data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 4, NULL);
	memcpy(laddr, data.bytes, j);
  }

  str[len] = '\0';
}

/* bug */
void writedata(pid_t child, unsigned long addr, char *str, int len)
{
  int i = 0;
  int j = len / long_size;
  char *laddr = str;
  union u_data data;

  while (i < j) {
	memcpy(data.bytes, laddr, long_size);
	ptrace(PTRACE_POKEDATA, child, addr + i * 4, data.val);
	++i;
	laddr += long_size;
  }

  j = len % long_size;
  if (j != 0) {
	union u_data mask;
	mask.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 4, NULL);
	memcpy(mask.bytes, laddr, j);
	ptrace(PTRACE_POKEDATA, child, addr + i * 4, mask.val);
  }
}

int x86_dump_asm(pid_t child, unsigned long address, int view)
{
  char line[CMDLINE_LEN];
  char buf[20];
  int pos = 0;
  int size;
  x86_insn_t insn;

  readdata(child, address, buf, sizeof(buf));
  
  x86_init(opt_none, NULL, NULL);
  
  size = x86_disasm(buf, sizeof(buf), 0, pos, &insn);
  if (size) {
	x86_format_insn(&insn, line, CMDLINE_LEN, intel_syntax);
	if (view) {
	  printf("<0x%08lx> - %s\n", address, line);
	}
	pos += size;
  }

  x86_cleanup();

  return pos;
}

int dbg_repl(pid_t child, int status, struct user_regs_struct *regs)
{
  char cmdline[CMDLINE_LEN];
  char *tp;
  int ret, i;
  char *saveptr;
  
  do {	
	ret = TDBG_DONOTHING;
	
	if (fgets(cmdline, CMDLINE_LEN, stdin) == NULL) {
	  perror("fgets");
	  return 0;
	}
	
	if (cmdline[0] == '\n') {
	  continue;
	}
	
	cmdline[strlen(cmdline)-1] = '\0';
	tp = strtok_r(cmdline, delim, &saveptr);

	for (i = 0 ; i < numofcmd ; i++) {
	  char *cmd = cmd_resources[i].command_name;
	  char *alias = cmd_resources[i].alias;
	  
	  if (strcmp(cmd, tp) == 0 || strcmp(alias, tp) == 0) {
		printf("Command: %s\n", tp);
		ret = cmd_resources[i].func(child, status, regs, &saveptr);
		break;
	  }
	}

	if (i >= numofcmd) {
	  printf("Can't recognize command: %s\n", cmdline);
	}
	
  } while (ret == TDBG_DONOTHING);
  
  return ret;
}

void signal_handler(int sig)
{
  //printf("Process %ld received signal %d\n", (long)getpid(), sig);
}

int set_next_action(pid_t child, int action_type)
{
  switch (action_type) {
  case TDBG_CONTINUE:
#ifdef __USE_SOFTWARE_BP
	ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
#endif
#ifdef __USE_HARDWARE_BP
	ptrace(PTRACE_CONT, child, NULL, NULL);
#endif
	break;
	
  case TDBG_STEP:
	ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
	break;
	
  case TDBG_EXIT:
	break;
	
  default:
	break;	
  }
  
  return 0;
}

void execute_debugger(void)
{
  int status = 0;
  int next_action = TDBG_STEP;
  pid_t child;
  struct user_regs_struct regs;
  
  printf("In debugger process %ld\n", (long)getpid());

/*   if (signal(SIGCHLD, signal_handler) == SIG_ERR) { */
/* 	perror("signal"); */
/* 	exit(-1); */
/*   } */

  do {
	int need_console = 0;
	
	static int inst_size = 0;
#ifdef __USE_HARDWARE_BP
	struct tdb_breakpoint *bp = NULL;
	static struct tdb_breakpoint *reset_bp = NULL;
	static struct tdb_breakpoint restore_bp;
	static int need_restore = 0;
#endif

	child = wait(&status);
	ptrace(PTRACE_GETREGS, child, NULL, &regs);
	
	if (WIFSTOPPED(status)) {
	  if (WSTOPSIG(status) == SIGTRAP) {
		need_console = (next_action == TDBG_STEP) ? 1 : 0;
#ifdef __USE_SOFTWARE_BP
		if (enable_bp && check_break_point(regs.eip)) {
		  printf("Hit break point (eip: 0x%08lx)\n", regs.eip);
		  need_console = 1;
		}
#endif
#ifdef __USE_HARDWARE_BP
		if (enable_bp) {
		  need_console = 1;
		  regs.eip -= 1; /* int3 */
		  bp = check_break_point(regs.eip);
		  
		  if (bp != NULL) {
			printf("Hit break point (eip: 0x%08lx)\n", regs.eip);
			/* write back old instruction */
			restore_inst(child, bp);
			
			reset_bp = bp;
			need_restore = 1;
		  } else if (need_restore && restore_bp.valid) {
			/* ブレークポイント復帰用のブレークポイントを削除 */
			restore_inst(child, &restore_bp);

			/* ブレークポイント復帰 */
			inject_int3(child,
						reset_bp->address,
						reset_bp->backupcode.bytes,
						reset_bp->backupcode_size);
			
			restore_bp.valid = -1;			
			need_console = need_restore = 0;
			inst_size = x86_dump_asm(child, regs.eip, 0);
		  }
		}
#endif
	  } else if (WSTOPSIG(status) == SIGSEGV) {
		printf("Segmentation fault\n");
	  } else {
		printf("debuggee has stopped due to signal %d\n", WSTOPSIG(status));
	  }
	}
	
	if (WIFSIGNALED(status)) {
	  printf("debuggee %d received signal %d\n", (int)child, WTERMSIG(status));
	  need_console = 1;
	}

	if (need_console) {
	  printf("The process stopped, putting back debuggee\n");
	  printf("Enter <help> to show manual\n");
	  inst_size = x86_dump_asm(child, regs.eip, 1);
	  next_action = dbg_repl(child, status, &regs);
	} else {
	  next_action = TDBG_CONTINUE;
	}

#ifdef __USE_HARDWARE_BP
	if (need_restore) {
	  /* ブレークポイント復帰用のブレークポイントを設定 */
	  restore_bp.valid = 1;
	  restore_bp.address = regs.eip + inst_size;
	  restore_bp.backupcode.val = 0;
	  restore_bp.backupcode_size = sizeof(dbg_code);
	  
	  inject_int3(child,
				  restore_bp.address,
				  restore_bp.backupcode.bytes,
				  restore_bp.backupcode_size);
	}
#endif

	ptrace(PTRACE_SETREGS, child, NULL, &regs);

	/* set next action */
	set_next_action(child, next_action);
	
  } while (!WIFEXITED(status));

  if (WIFEXITED(status)) {
	int exit_status = WEXITSTATUS(status);
	printf("Program exited with status (%d)\n", exit_status);
  }

  return;
}

void execute_debuggee(void)
{
  char* argv[] = { "/tmp", NULL };
  char* envp[] = { NULL };
  
  printf("In debuggie process %ld\n", (long)getpid());

  if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)) {
	perror("ptrace");
	return;
  }

  execve("./debuggee", argv, envp);
}

void test_bp(void)
{
#ifdef __USE_SOFTWARE_BP
  printf("BPTABLE_SIZE: %ld\n", BPTABLE_SIZE);
  printf("BPTABLE_MASK: 0x%08lx\n", (~(BPTABLE_SIZE - 1)));
  
  printf("test init bp\n");
  init_bptable();
  printf("done\n");

  printf("test setting bp\n");
  set_break_point(0x10203040);
  set_break_point(0xffffffff);
  set_break_point(0x11111111);
  set_break_point(0x22222222);
  set_break_point(0x43dafe43);
  printf("done\n");

  printf(" pretty print bp list\n");
  enum_bp_list();
  printf("done\n");
  
  printf("all clear bp");
  clear_break_point(0x10203040);
  clear_break_point(0xffffff00);
  clear_break_point(0x11111111);
  clear_break_point(0x22222220);
  clear_break_point(0x43dafe00);
  printf("done\n");

  printf(" pretty print bp list\n");
  enum_bp_list();
  printf("done\n");

  printf(" free al bp\n");
  free_all_bptable();
  printf("done\n");
#endif
  return;
}

int main(int argc, char *argv[])
{
  pid_t child;

  //  test_bp();
  
  child = fork();
  if (child == 0) {
	/* child process */
	execute_debuggee();
  } else if (child > 0) {
	
#ifdef __USE_SOFTWARE_BP
	init_bptable();
#endif
#ifdef __USE_HARDWARE_BP
	init_bptable(child);
#endif
	
	/* debugger process */
	execute_debugger();
	
#ifdef __USE_SOFTWARE_BP
	free_all_bptable();
#endif
#ifdef __USE_HARDWARE_BP
	free_all_bptable(child);
#endif
	
  } else {
	perror("fork");
	return -1;
  }
  
  return 0;
}

