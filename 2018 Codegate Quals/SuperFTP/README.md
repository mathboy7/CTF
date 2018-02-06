SuperFTP - Pwn 600pt (13 Teams Solved)
-------------
## Description
SuperFTP is simple x86-menu challenge with ASLR+NX+SSP+PIE+Full RELRO.

## Reversing
Program provide 8 menus.

1. Join
2. Print your information
3. Login
4. Withdrawal
5. Download Files
6. exit
7, 8 -> hidden menus

There is **info_ptr** pointer for manage account information at $ebp-0x20 of main stack.
The members of info structure are:
```c
struct info
{
  String id;
  String pw;
  String name;
  int age;
};
```

### Join
Program recieves name, age, id, pw and create info structure.
Stores info structure ptr at info_ptr.

### Print your information
Check login flag, print information (name, age, id) of user if flag is valid.

### Login
Program recieves id and pw from user.
A buffer overflow occurs because the program uses the cin () function when it receives a buffer and the buffer it receives is not a String object. (BTW I didn't used this vuln to exploit.)
If the ID and password match with "admin" and "P3ssw0rd", activate the admin flag and the login flag. If they do not match the admin information but match the user information, only the login flag is activated.
After login() function called, code increment/decrements the main scope variable "loginCnt" depending on result of login().

### Withdrawal
Free info_ptr, info_ptr->id, info_ptr->pw, info_ptr->name and nullify info_ptr if login flag is valid.

### Download Files
First, downloadFile() menu recieves URL string.
Menu replaces string such as "/home/mathboy7/pwn/../bb" to "/home/mathboy7/bb".
The algorithm used in this process is as follows.

1. Recieves URL. ("/home/mathboy7/pwn/../bb")
2. Reverse string ("bb/../nwp/7yobhtam/emoh/"), g_URL points start of reversed string.
3. Search "/../" pattern. Variable ptr1 points "/../nwp/7yobhtam/emoh/" now.
4. Search "/" corresponding to "/../" and stores to ptr2. In this case, ptr2 points "/7yobhtam/emoh/".
5. Copy [start ~ "/../"] before ptr2 => ("bb/7yobhtam/emoh/")
6. Reverse string again, ptr points "/home/mathboy7/bb" now!

Simple XD

### Hidden menu1 (menu 7)
Not important.

### Hidden menu2 (menu 8)
provide 4 menus, menu 2/3/4 is not important.
menu 1 performs exactly same behavior with "Download Files" menu.

The only difference is that g_URL points to the stack buffer.

## Vulnerability
There are multiple vulnerability in this program but there is only one vulnerability that you should really pay attention to.

If you focus at binary code, you can find that there is no boundary check at "Download Files" menu.

More specifically, if the URL has "/../" pattern without the corresponding "/" character, it will exceed the range of URL buffer when searching for the "/" character.

## Exploit
"loginCnt" variable is located in stack of main().
If we try to login multiple time to set loginCnt 0x2f, we can write our payload to stack of main().
Let's take a simple look of stack structure.

```
============ <= stack of main
...
login_cnt    <= copy payload.reverse() until ret, before canary.
...
============ <= stack of menu 8
...
ret
...
canary
...
============ <= stack of downloadURL
```

So we can overwrite menu 8's return address without touching canary.

The final exploit flow is shown below.

1. Login with admin
2. Download URL with "/../aa/../", leak pointer of libc.
3. Set loginCnt to 0x2f.
4. Send payload and overwrite menu 8's return address.

```
$ id
uid=1000(ftp) gid=1000(ftp) groups=1000(ftp)
$ 
$ cat flag
Sorry_ftp_1s_brok3n_T_T@
$ 
```
