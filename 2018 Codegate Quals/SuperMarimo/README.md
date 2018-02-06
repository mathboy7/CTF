There is heap overflow vulnerability in Edit menu.
We can modify string pointer of next chunk to GOT and leak libc, overwrite GOT to one_shot gadget.
easy XD
