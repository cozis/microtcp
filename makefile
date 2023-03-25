all: loop2

loop2:
	gcc src/arp.c src/ip.c src/icmp.c src/tcp.c src/microtcp.c test/loop2.c -o loop2 -Wall -Wextra -g -DARP_DEBUG -DMICROTCP_DEBUG -DIP_DEBUG -DICMP_DEBUG -DTCP_DEBUG -DMICROTCP_BACKGROUND_THREAD -DMICROTCP_USING_TAP -pthread -ltuntap -Iinclude/ -I3p/include/ -L3p/lib/

loop:
	gcc src/arp.c src/ip.c src/icmp.c src/tcp.c src/microtcp.c src/microtcp_linux.c test/loop.c -o loop -Wall -Wextra -g -DARP_DEBUG -DMICROTCP_DEBUG -DIP_DEBUG -DICMP_DEBUG -DTCP_DEBUG -DMICROTCP_BACKGROUND_THREAD -DMICROTCP_LINUX -pthread -Iinclude/ # -fsanitize=thread

test_arp:
	gcc src/arp.c test/test_arp.c test/test_arp_util.c -o test_arp -Wall -Wextra -g -Iinclude/

test_arp_cov:
	gcc src/arp.c test/test_arp.c test/test_arp_util.c -o test_arp_cov -Wall -Wextra -g -fprofile-arcs -ftest-coverage -lgcov

report_arp_cov: test_arp_cov
	./test_arp_cov
	lcov --capture --directory . --output-file coverage.info --rc lcov_branch_coverage=1
	genhtml coverage.info --output-directory report_arp_cov --rc lcov_branch_coverage=1
	rm *.gcda *.gcno coverage.info

clean:
	rm -f loop