SuperFTP - Pwn 600pt (13 Teams Solved)
-------------
### Description
SuperFTP is simple x86-menu challenge with ASLR+NX+SSP+PIE+Full RELRO.

### Program Overview
Program provide 8 menus.

1. Join
2. Print your information
3. Login
4. Withdrawal
5. Download Files
6. exit
7, 8 -> hidden menus

There is info pointer for manage account information at $ebp-0x20 of main stack.

```c
struct info
{
  String id;
  String pw;
  String name;
  int age;
};
```
