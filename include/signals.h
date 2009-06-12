#include <ev.h>

struct ev_loop;
struct ev_signal;

struct signals
{
	struct ev_signal sigint;
	struct ev_signal sighup;
};


void sigint_cb(struct ev_loop *loop, struct ev_signal *w, int revents);
void sighup_cb(struct ev_loop *loop, struct ev_signal *w, int revents);

