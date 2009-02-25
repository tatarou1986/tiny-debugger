
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int graph = 0;

int test();

int main(int argc, char *argv[]) {
  test();
  exit(0);
}

int test() {
  while(1) {
	printf(" hello world\n");
	sleep(1);
  }
}

