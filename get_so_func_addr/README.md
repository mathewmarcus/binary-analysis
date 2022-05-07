# get_so_func_addr

CLI utility for dynamically computing the load address of exported shared library functions referenced in an ELF executable.

## [Building](../README.md#building)

## Usage
`get_so_func_addr PROC_NAME LIB_PATH LIB_FUNC_NAME`

### Example
Consider an HTTP server - `httpd`. To discover the dynamic load address of the `recv` function which is exported by the `libc` library:

```bash
$ get_so_func_addr httpd /lib/x86_64-linux-gnu/libc.so.6 recv
httpd PID: 73780
libc-2.31.so load address: 0x7f786b36c000
recv offset: 0x00120320
0x7f786b48c320
```

`gdb` can be used to verify:

```bash
$ gdb -q --pid=73780 `which httpd`
(gdb) info sym 0x7f786b48c320
recv in section .text of /lib/x86_64-linux-gnu/libc.so.6
```
