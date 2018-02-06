There is heap overflow vulnerability in Edit menu.<br>
We can modify string pointer of profile pointer to GOT and leak libc, overwrite GOT to one_shot gadget.<br>
easy XD
