# processtracer
Process tracer tool using intel pin dbi (for linux and windows). Tool dumps process execution with memory access and context information.

## build
get latest pin from [intel pin download](https://software.intel.com/content/www/us/en/develop/articles/pin-a-binary-instrumentation-tool-downloads.html) and extract it locally

### Linux
```
# build x64 version with command
PIN_ROOT=../../../frameworks/pin-3.10 make
# which will build tool proctracer.so in obj-intel64 directory

# build x86 version with command
TARGET=ia32 PIN_ROOT=../../../frameworks/pin-3.10 make
# which will build tool proctracer.so in obj-ia32 directory
```

### Windows
You will need windows version of PIN and visual studio 2017.
Make copy of existing MyPinTool template project from PIN tools source and include proctracer.cpp and proctracer.h to the solution and build solution.

## Running Tool
Using tool on both linux and windows is similar process
```
$PIN_ROOT/pin -t obj-intel64/proctracer.so <tool-options> -- /path/to/bin <bin-options>
```

## ProcTracer options
```
-b  [default 0]     enable if you want to log basic block trace
-c  [default 0]     enable if you want to trace function calls
-fm  [default main] filter module to trace, default is main executable
-fo  [default ]     comma separated list of filter offsets relative to filter module in form of 0x100-0x200,...
-hx  [default 0]    enable if you want to have hex dump of the memory
-i  [default 0]     enable if you want to trace instructions
-m  [default 0]     enable if you want to trace module load/unload activity
-o  [default trace-full-info.txt]   specify trace file name
-syscalls  [default 0]  enable if you want to trace syscalls
-t  [default 0]     enable if you want to trace threads activities
-h  [default 0]     
-help  [default 0]  
                    Print help message (Return failure of PIN_Init() in order to allow the tool to print help message)
```

## Examples

### listing all calls issued in module
```
# ../../../frameworks/pin-3.10/pin -t obj-intel64/proctracer.so -c -- /bin/ls 
# head trace-full-info.txt 
 > call in thread#0 from: 0x55ff4825d874 to: 0x7f1523b7bab0 __libc_start_main args ( 0x55ff4825be90, 0x1, 0x7fffc76c53b8)
 > call in thread#0 from: 0x55ff4826e2ec to: 0x55ff4825b758 _init args ( 0x1, 0x7fffc76c53b8, 0x7fffc76c53c8)
 > call in thread#0 from: 0x55ff4826e309 to: 0x55ff4825d950 .text args ( 0x1, 0x7fffc76c53b8, 0x7fffc76c53c8)
 > call in thread#0 from: 0x55ff4825beb6 to: 0x55ff48269fd0 .text args ( 0x7fffc76c5d5b, 0x7fffc76c53b8, 0x7fffc76c53c8)
 > call in thread#0 from: 0x55ff48269fde to: 0x55ff4825b9e0 strrchr@plt args ( 0x7fffc76c5d5b, 0x2f, 0x7fffc76c53c8)
 > call in thread#0 from: 0x55ff4825bec7 to: 0x55ff4825bcc0 setlocale@plt args ( 0x6, 0x55ff4826fc4a, 0x7fffc76c5d60)
 > call in thread#0 from: 0x55ff4825beda to: 0x55ff4825b920 bindtextdomain@plt args ( 0x55ff4826fd7b, 0x55ff4826fd95, 0x0)
    ....
``` 
### listing all calls issued in module with memory dump
```
# ../../../frameworks/pin-3.10/pin -t obj-intel64/proctracer.so -c -hx -- /bin/ls 
# head trace-full-info.txt 
 > call in thread#0 from: 0x55d8a27eb874 to: 0x7faf1b556ab0 __libc_start_main args ( 0x55d8a27e9e90, 0x1, 0x7fff10f83568)
                                                             arg0 dump
                                                                    0x00000000a27e9e90 41 57 41 56 41 55 41 54 55 53 89 fd 48 89 f3 48  AWAVAUATUS..H..H
                                                                    0x00000000a27e9ea0 83 ec 58 48 8b 3e 64 48 8b 04 25 28 00 00 00 48  ..XH.>dH..%(...H
                                                                    0x00000000a27e9eb0 89 44 24 48 31 c0 e8 15 e1 00 00 48 8d 35 88 3d  .D$H1......H.5.=
                                                                    0x00000000a27e9ec0 01 00 bf 06 00 00 00 e8 f4 fd ff ff 48 8d 35 c2  ............H.5.
                                                             arg1 dump
                                                             arg2 dump
                                                                    0x0000000010f83568 5b 3d f8 10 ff 7f 00 00 00 00 00 00 00 00 00 00  [=..............
                                                                    0x0000000010f83578 63 3d f8 10 ff 7f 00 00 72 3d f8 10 ff 7f 00 00  c=......r=......
                                                                    0x0000000010f83588 84 3d f8 10 ff 7f 00 00 a2 3d f8 10 ff 7f 00 00  .=.......=......
                                                                    0x0000000010f83598 f5 3d f8 10 ff 7f 00 00 00 3e f8 10 ff 7f 00 00  .=.......>......
```

### listing module load/unload and threading activity (using -m and -t option)
```
# ../../../frameworks/pin-3.10/pin -t obj-intel64/proctracer.so -m -t -- /bin/ls
# look into trace-full-info.txt 

* module loaded - /bin/ls 5618912a5000:5618912c36e7
* module loaded - /lib64/ld-linux-x86-64.so.2 7ff174c46000:7ff174c6cc23
* module loaded - [vdso] 7ffcb6dd5000:7ffcb6dd5ae6
    * new thread started with id#0
* module loaded - /lib/x86_64-linux-gnu/libselinux.so.1 7ff160582000:7ff1607a98cf
...
    * thread with id#0 ended
* module unloaded - /bin/ls 5618912a5000:5618912c36e7
* module unloaded - /lib64/ld-linux-x86-64.so.2 7ff174c46000:7ff174c6cc23
...
```

### process tracing and instruction dumps (using -i option and filter offsets)
```
# ../../../frameworks/pin-3.10/pin -t obj-intel64/proctracer.so -i -- ../../foo 
# ../../../frameworks/pin-3.10/pin -t obj-intel64/proctracer.so -i -fo 0x65a-0x6dc -- ../../foo 

tid#0: module+0x65a| 55                       push rbp                      rbp=0x5568ac3a76e0 flags=0x246
                                                                 Write in thread#0 from loc 0x5568ac3a765a on addr 0x7ffc7bb5e710 of 8 bytes, value=5568ac3a76e0
tid#0: module+0x65b| 48 89 e5                 mov rbp, rsp                  rsp=0x7ffc7bb5e710 rbp=0x5568ac3a76e0 flags=0x246
tid#0: module+0x65e| 48 83 ec 20              sub rsp, 0x20                 rsp=0x7ffc7bb5e710 flags=0x246
tid#0: module+0x662| 89 7d ec                 mov dword ptr [rbp-0x14], edi rdi=0x2 rbp=0x7ffc7bb5e710 flags=0x206
                                                                 Write in thread#0 from loc 0x5568ac3a7662 on addr 0x7ffc7bb5e6fc of 4 bytes, value=2
...
```

### process tracing and instruction dumps with basic blocks and full context information (using -b option)
```
# ../../../frameworks/pin-3.10/pin -t obj-intel64/proctracer.so -i -b -fo 0x65a-0x6dc -- ../../foo

basic block in #thread0 0x55d72824365a of size 15 (main)
CPU Context:
                           rax=0x55d72824365a rbx=0x0 rcx=0x55d7282436e0 rdx=0x7ffed60ec270
                           rdi=0x2 rsi=0x7ffed60ec258 rsp=0x7ffed60ec178 rbp=0x55d7282436e0
                           rip=0x55d72824365a r8=0x7f06a1800d80 r9=0x7f06a1800d80 r10=0x2
                           r11=0x7 r12=0x55d728243550 r13=0x7ffed60ec250 r14=0x0
                           r15=0x0 fs=0x0 gs=0x0 flags=0x246
tid#0: module+0x65a| 55                       push rbp                      rbp=0x55d7282436e0 flags=0x246
                                                                 Write in thread#0 from loc 0x55d72824365a on addr 0x7ffed60ec170 of 8 bytes, value=55d7282436e0
tid#0: module+0x65b| 48 89 e5                 mov rbp, rsp                  rsp=0x7ffed60ec170 rbp=0x55d7282436e0 flags=0x246
```

### process tracing and instruction dumps with basic blocks and full context information and memory dumps (using -hx option)
```
# ../../../frameworks/pin-3.10/pin -t obj-intel64/proctracer.so -i -b -hx -fo 0x65a-0x6dc -- ../../foo

basic block in #thread0 0x562e50d3365a of size 15 (main)
CPU Context:
                           rax=0x562e50d3365a rbx=0x0 rcx=0x562e50d336e0 rdx=0x7fff15799a70
                           rdi=0x2 rsi=0x7fff15799a58 rsp=0x7fff15799978 rbp=0x562e50d336e0
                           rip=0x562e50d3365a r8=0x7fea522cad80 r9=0x7fea522cad80 r10=0x2
                           r11=0x7 r12=0x562e50d33550 r13=0x7fff15799a50 r14=0x0
                           r15=0x0 fs=0x0 gs=0x0 flags=0x246
tid#0: module+0x65a| 55                       push rbp                      rbp=0x562e50d336e0 flags=0x246
                                                                 Write in thread#0 from loc 0x562e50d3365a on addr 0x7fff15799970 of 8 bytes, value=562e50d336e0
                                                                    0x0000000015799970 e0 36 d3 50 2e 56 00 00 97 fb ef 51 ea 7f 00 00  .6.P.V.....Q....
                                                                    0x0000000015799980 02 00 00 00 00 00 00 00 58 9a 79 15 ff 7f 00 00  ........X.y.....
                                                                    0x0000000015799990 00 80 00 00 02 00 00 00 5a 36 d3 50 2e 56 00 00  ........Z6.P.V..
                                                                    0x00000000157999a0 00 00 00 00 00 00 00 00 3c 65 f8 24 c3 13 74 ad  ........<e.$..t.
tid#0: module+0x65b| 48 89 e5                 mov rbp, rsp                  rsp=0x7fff15799970 rbp=0x562e50d336e0 flags=0x246
tid#0: module+0x65e| 48 83 ec 20              sub rsp, 0x20                 rsp=0x7fff15799970 flags=0x246
tid#0: module+0x662| 89 7d ec                 mov dword ptr [rbp-0x14], edi rdi=0x2 rbp=0x7fff15799970 flags=0x206
                                                                 Write in thread#0 from loc 0x562e50d33662 on addr 0x7fff1579995c of 4 bytes, value=2
                                                                    0x000000001579995c 02 00 00 00 50 9a 79 15 ff 7f 00 00 00 00 00 00  ....P.y.........
                                                                    0x000000001579996c 00 00 00 00 e0 36 d3 50 2e 56 00 00 97 fb ef 51  .....6.P.V.....Q
```

### dump syscalls
```
# ../../../frameworks/pin-3.10/pin -t obj-intel64/proctracer.so -syscalls -hx -- ../../foo

    > syscall 0xc
            arg0: 0x0
            arg1: 0x50
            arg2: 0x4d
        > syscall returned 0x5565c691a000
    > syscall 0x15
            arg0: 0x7fe8756ae082
                                                                    0x00000000756ae082 2f 65 74 63 2f 6c 64 2e 73 6f 2e 6e 6f 68 77 63  /etc/ld.so.nohwc
                                                                    0x00000000756ae092 61 70 00 63 61 6e 6e 6f 74 20 63 72 65 61 74 65  ap.cannot create
                                                                    0x00000000756ae0a2 20 63 61 70 61 62 69 6c 69 74 79 20 6c 69 73 74   capability list
                                                                    0x00000000756ae0b2 00 74 6c 73 00 64 6c 2d 68 77 63 61 70 73 2e 63  .tls.dl-hwcaps.c
            arg1: 0x0
            arg2: 0x17
        > syscall returned 0xffffffffffffffff

```

## Credits
Based on code written by

Philippe Teuwen @doegox for his [TracerPIN](https://github.com/SideChannelMarvels/Tracer/tree/master/TracerPIN)
