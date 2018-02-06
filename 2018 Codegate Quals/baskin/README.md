There is stack buffer overflow vulnerability in your_turn() function.<br>
Problem kindly provides some gadgets to make life easy.<br>
Use write() function to leak libc address.<br>
Change control flow to main() again, call system("/bin/sh").
