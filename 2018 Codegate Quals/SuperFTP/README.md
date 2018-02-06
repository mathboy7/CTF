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


### Hidden menu1 (menu 7)
Not important.

### Hidden menu2 (menu 8)
provide 4 menus, menu 2/3/4 is not important.
menu 1 performs exactly same behavior with "Download Files" menu.

The only difference is that g_URL points to the stack buffer.
