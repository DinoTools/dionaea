AC_DEFUN([AZ_FUNC_BIND_MAPPED_IPV4_LOCALHOST],
[AC_CHECK_FUNCS(bind)
AC_MSG_CHECKING([if bind("::ffff:0.0.0.0") works])
AC_CACHE_VAL(ac_cv_have_bind_ipv4_mapped_localhost,
[AC_RUN_IFELSE(
[#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

int main(int argc, char **argv)
{
	int s = socket(PF_INET6, SOCK_STREAM, 0);
	int r = -1;
	struct sockaddr_in6 si6;
	memset(&si6,0,sizeof(struct sockaddr_in6));
	inet_pton(PF_INET6, "::ffff:0.0.0.0", &si6.sin6_addr);
	si6.sin6_family = PF_INET6;
	r = bind(s, (struct sockaddr *)&si6, sizeof(struct sockaddr_in6));
	close(s);
	return r;
}], ac_cv_have_bind_ipv4_mapped_localhost=yes, ac_cv_have_bind_ipv4_mapped_localhost=no, ac_cv_have_bind_ipv4_mapped_localhost=cross)])
AC_MSG_RESULT([$ac_cv_have_bind_ipv4_mapped_localhost])
])
