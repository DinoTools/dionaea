Segfault
========

In case you experience a segfault, you will see something like this:

This is the end.
This software just had a segmentation fault.
The bug you encountered may even be exploitable.
If you want to assist in fixing the bug, please send the backtrace below to nepenthesdev@gmail.com.
You can create better backtraces with gdb, for more information visit http://dionaea.carnivore.it/#segfault
Once you read this message, your tty may be broken, simply type reset, so it will come to life again

/opt/dionaea/bin/dionaea(sigsegv_backtrace_cb+0x20)[0x805c11e]
[0x70d420]
/opt/dionaea/lib/libemu/libemu.so.2(emu_env_w32_eip_check+0x94)[0x186974]
/opt/dionaea/lib/dionaea/emu.so(run+0x39)[0x89cced]
/opt/dionaea/lib/dionaea/emu.so(profile+0xbb)[0x89db88]
/opt/dionaea/lib/dionaea/emu.so(proc_emu_on_io_in+0x1e1)[0x89bfc5]
/opt/dionaea/bin/dionaea(recurse_io_process+0x31)[0x805df4a]
/opt/dionaea/bin/dionaea(processors_io_in_thread+0x85)[0x805e08d]
/opt/dionaea/bin/dionaea(threadpool_wrapper+0x2e)[0x805c99a]
/opt/dionaea/lib/libglib-2.0.so.0[0xaa9498]
/opt/dionaea/lib/libglib-2.0.so.0[0xaa7a2f]
/lib/libpthread.so.0[0xd8973b]
/lib/libc.so.6(clone+0x5e)[0x2b3cfe]

While the backtrace itself gives an idea what might be wrong, it does
not fix the problem. To fix the problem, the logfiles usually help, as
dionaea is very verbose by default. Below are some hints how to get
started with debugging, click here <#support> for assistance.


      debugging


        Valgrind

Valgrind does a great job, here is how I use it:

valgrind -v --leak-check=full --leak-resolution=high --show-reachable=yes \
--log-file=dionaea-debug.log /opt/dionaea/bin/dionaea --my-dionaea-options


        gdb


          logfile assisted

For the above example, I was able to scrape the shellcode from the
logfile, and run it in libemu, without involving dionaea at all,
reducing the problem.

gdb /opt/dionaea/bin/sctest
(gdb) run -S -s 10000000 -g < sc.bin
Starting program: /media/sda4/opt64/dionaea/bin/sctest -S -s 10000000 -g < sc.bin

Once it crashed, I retrieved a full backtrace:

Program received signal SIGSEGV, Segmentation fault.
env_w32_hook_GetProcAddress (env=0x629a30, hook=<value optimized out>) at environment/win32/env_w32_dll_export_kernel32_hooks.c:545
545                             struct emu_env_hook *hook = (struct emu_env_hook *)ehi->value;

(gdb) bt full
#0  env_w32_hook_GetProcAddress (env=0x629a30, hook=<value optimized out>) at environment/win32/env_w32_dll_export_kernel32_hooks.c:545
        dll = 0x6366f0
        ehi = <value optimized out>
        hook = <value optimized out>
        c = 0x611180
        mem = <value optimized out>
        eip_save = <value optimized out>
        module = 2088763392
        p_procname = 4289925
        procname = <value optimized out>
#1  0x00007ffff7b884fb in emu_env_w32_eip_check (env=0x629a30) at environment/win32/emu_env_w32.c:306
        dll = <value optimized out>
        ehi = <value optimized out>
        hook = 0x64c5b0
        eip = <value optimized out>
#2  0x0000000000403995 in test (e=0x60f0e0) at sctestmain.c:277
        hook = 0xe2
        ev = 0x0
        iv = <value optimized out>
        cpu = 0x611180
        mem = <value optimized out>
        env = 0x629a30
        na = <value optimized out>
        j = 7169
        last_vertex = 0x0
        graph = 0x0
        eh = 0x0
        ehi = 0x0
        ret = <value optimized out>
        eipsave = 2088807840
#3  0x00000000004044e4 in main (argc=5, argv=0x7fffffffe388) at sctestmain.c:971
        e = <value optimized out>

In this case, the problem was a bug in libemu.


          gdb dump memory

Once again, it broke, and we got a backtrace:

#0  0xb70b0b57 in emu_queue_enqueue (eq=0xb3da0918, data=0x4724ab) at emu_queue.c:63
        eqi = (struct emu_queue_item *) 0x0
#1  0xb70b15d1 in emu_shellcode_run_and_track (e=0xb4109cd0, data=0xb411c698 "", datasize=<value optimized out>, eipoffset=<value optimized out>,
    steps=256, etas=0xb410cd60, known_positions=0xb3d7a810, stats_tested_positions_list=0xb3da3bf0, brute_force=true) at emu_shellcode.c:408
        current_pos_ti_diff = (struct emu_tracking_info *) 0x88c3c88
        current_pos_ht = <value optimized out>
        current_pos_v = <value optimized out>
        current_pos_satii = (struct emu_source_and_track_instr_info *) 0xb407e7f8
        bfs_queue = (struct emu_queue *) 0xb3e17668
        ret = 4662443
        eipsave = <value optimized out>
        hook = <value optimized out>
        j = 4
        es = <value optimized out>
        eli = (struct emu_list_item *) 0xb3e17658
        cpu = (struct emu_cpu *) 0xb4109ab0
        mem = (struct emu_memory *) 0xb410c3a0
        eq = (struct emu_queue *) 0xb3da0918
        env = (struct emu_env *) 0xb3e10208
        eli = (struct emu_list_item *) 0x4724ab
#2  0xb70b1a2a in emu_shellcode_test (e=0xb4109cd0, data=0xb411c698 "", size=<value optimized out>) at emu_shellcode.c:546
        es = (struct emu_stats *) 0xb3d92b28
        new_results = (struct emu_list_root *) 0xb3da3bf0
        offset = <value optimized out>
        el = (struct emu_list_root *) 0xb4100510
        etas = (struct emu_track_and_source *) 0xb410cd60
        eh = (struct emu_hashtable *) 0xb3d7a810
        eli = (struct emu_list_item *) 0xb3d92b40
        results = (struct emu_list_root *) 0xb3d82850
        es = <value optimized out>
        __PRETTY_FUNCTION__ = "emu_shellcode_test"
#3  0xb712140c in proc_emu_on_io_in (con=0x8864b58, pd=0x87dc388) at detect.c:145
        e = (struct emu *) 0xb4109cd0
        ctx = (struct emu_ctx *) 0x87a2400
        offset = 14356
        streamdata = (void *) 0xb411c698
        size = 8196
        ret = 0
        __PRETTY_FUNCTION__ = "proc_emu_on_io_in"
#4  0x0805e8be in recurse_io_process (pd=0x87dc388, con=0x8864b58, dir=bistream_in) at processor.c:167
No locals.
#5  0x0805ea01 in processors_io_in_thread (data=0x8864b58, userdata=0x87dc388) at processor.c:197
        con = (struct connection *) 0x8864b58
        pd = (struct processor_data *) 0x87dc388
        __PRETTY_FUNCTION__ = "processors_io_in_thread"
#6  0x0805d2da in threadpool_wrapper (data=0x87d7bd0, user_data=0x0) at threads.c:49
        t = (struct thread *) 0x87d7bd0
        timer = (GTimer *) 0xb4108540
#7  0xb77441f6 in g_thread_pool_thread_proxy (data=0x83db460) at gthreadpool.c:265
        task = (gpointer) 0x87d7bd0
        pool = (GRealThreadPool *) 0x83db460
#8  0xb7742b8f in g_thread_create_proxy (data=0x83dc7d0) at gthread.c:635
        __PRETTY_FUNCTION__ = "g_thread_create_proxy"
#9  0xb76744c0 in start_thread () from /lib/i686/cmov/libpthread.so.0
No symbol table info available.
#10 0xb75f36de in clone () from /lib/i686/cmov/libc.so.6
No symbol table info available.

Again, it was a bug in libemu, an unbreakable loop consuming all memory.
To reproduce, we have to dump the tested buffer, therefore we need the
buffers address and size. Luckily the size is noted in frame #2 as 8196
and and the data address is a parameter which got not optimized out for
frame #2.

dump binary memory /tmp/sc.bin 0xb411c698 0xb411e89c

Afterwards, debugging libemu by feeding the data into sctest is easy.

I've had fun with objgraph and gdb debugging reference count leaks in
python too, here <http://carnivore.it/2009/12/23/arcane_bugs> is the
writeup.


          gdb python3 embedded

Sometimes, there is something wrong with the python scripts, but gdb
does not provide any useful output:

bt full
#12 0xb765f12d in PyEval_EvalFrameEx (f=0x825998c, throwflag=0) at Python/ceval.c:2267
        stack_pointer = (PyObject **) 0x8259af0
        next_instr = (unsigned char *) 0x812fabf "m'"
        opcode = 100
        oparg = <value optimized out>
        why = 3071731824
        err = 1
        x = (PyObject *) 0xb7244aac
        v = <value optimized out>
        w = (PyObject *) 0xadb5e4dc
        u = (PyObject *) 0xb775ccb0
        freevars = (PyObject **) 0x8259af0
        retval = (PyObject *) 0x0
        tstate = (PyThreadState *) 0x809aab0
        co = (PyCodeObject *) 0xb717b800
        instr_ub = -1
        instr_lb = 0
        instr_prev = -1
        first_instr = (unsigned char *) 0x812f918 "t"
        names = (PyObject *) 0xb723f50c
        consts = (PyObject *) 0xb71c9f7c
        opcode_targets = {0xb765d202, 0xb765f60a, 0xb766133a, 0xb76612db, 0xb7661285, 0xb7661222, 0xb765d202, 0xb765d202, 0xb765d202, 0xb76611dd,
  0xb766114b, 0xb76610b9, 0xb766100f, 0xb765d202, 0xb765d202, 0xb7660f7d, 0xb765d202, 0xb765d202, 0xb765d202, 0xb7660eb7, 0xb7660dfb, 0xb765d202,
  0xb7660d30, 0xb7660c65, 0xb7660ba9, 0xb7660aed, 0xb7660a31, 0xb7660975, 0xb76608b9, 0xb76607fd, 0xb765d202 <repeats 24 times>, 0xb7660736, 0xb766066b,
  0xb76605af, 0xb76604f3, 0xb765d202, 0xb7660437, 0xb766035d, 0xb76602ad, 0xb7661aba, 0xb76619fe, 0xb7661942, 0xb7661886, 0xb7661b76, 0xb76614a8,
  0xb7661413, 0xb766138e, 0xb766171f, 0xb76616e6, 0xb765d202, 0xb765d202, 0xb765d202, 0xb766162a, 0xb766156e, 0xb76601f1, 0xb7660135, 0xb76617ca,
  0xb7660120, 0xb765fff7, 0xb765d202, 0xb765fd72, 0xb765fc6e, 0xb765d202, 0xb765fc1d, 0xb765fe17, 0xb765fd90, 0xb765fec0, 0xb765fb41, 0xb765fadc,
  0xb765f9ed, 0xb765f94d, 0xb765f8be, 0xb765f7e3, 0xb765f779, 0xb765f6bd, 0xb765f66c, 0xb765ef1d, 0xb765eea2, 0xb765ede1, 0xb765ed1a, 0xb765ec35,
  0xb765ebc3, 0xb765eb30, 0xb765ea69, 0xb765f1c7, 0xb765f027, 0xb765f560, 0xb765efc1, 0xb76630e3, 0xb766310c, 0xb765e64c, 0xb765e592, 0xb765f49a,
  0xb765f3de, 0xb765d202, 0xb765d202, 0xb765f39e, 0xb7663135, 0xb766315f, 0xb765e9cb, 0xb765d202, 0xb765e948, 0xb765e8bb, 0xb765e817, 0xb765d202,
  0xb765d202, 0xb765d202, 0xb765d2ae, 0xb765e3e0, 0xb7663275, 0xb765e1a2, 0xb766324e, 0xb765e0ba, 0xb765e01e, 0xb765df74, 0xb765d202, 0xb765d202,
  0xb7663189, 0xb76631d3, 0xb7663220, 0xb765e149, 0xb765d202, 0xb765de09, 0xb765dec0, 0xb765f2c0, 0xb765d202 <repeats 108 times>}
#13 0xb7664ac0 in PyEval_EvalCodeEx (co=0xb717b800, globals=0xb7160b54, locals=0x0, args=0x84babb8, argcount=9, kws=0x0, kwcount=0, defs=0xb719e978,
    defcount=1, kwdefs=0x0, closure=0x0) at Python/ceval.c:3198
        f = (PyFrameObject *) 0x825998c
        retval = <value optimized out>
        freevars = (PyObject **) 0x8259af0
        tstate = (PyThreadState *) 0x809aab0
        x = <value optimized out>
        u = <value optimized out>

Luckily python3 ships with some gdb macros, which assist in dealing with
this mess. You can grab them over here
<http://svn.python.org/view/python/tags/r311/Misc/gdbinit?view=markup>,
place them to ~/.gdbinit, where ~ is the homedirectory of the user
dionaea runs as.
If you get /*warning: not using untrusted file "/home/user/.gdbinit"*/
you are running gdb via sudo, and the file /home/user/.gdbinit has to be
owned by root.
If you are running as root, and you get /*Program received signal
SIGTTOU, Stopped (tty output).*/, run stty -nostop before running gdb,
reattach the process with fg, close gdb properly, and start over.

Once you got the macros loaded properly at gdb startup, set a breakpoint
on PyEval_EvalFrameEx after dionaea loaded everything:

break PyEval_EvalFrameEx

Then we have some useful macros for gdb:

up
pyframev

pyframev combines the output of pyframe and pylocals.

Be aware you can segfault dionaea now from within gdb, going up, out of
the python call stack and calling some of the macros can and in most
cases will segfault dionaea, therefore use backtrace to make sure you
are still within valid frames.
We can't use pystack or pystackv as they rely on Py_Main, which is an
invalid assumption for embedded python.
