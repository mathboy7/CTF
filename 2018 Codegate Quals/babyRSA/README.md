Challenge provide two value, (d+p)^(d-p) and d*(p-0xdeadbeef).<br>
XOR is bit-dependent operation, so we know (d+p) ^ (d-p) = h => ((d+p) mod 2**k) ^ ((d-p) mod 2**k) -= h mod 2**k is true.<br>
So I made a list of (d, p) for every 5-bits, make 1024 awnsers of every available (d, p).<br>
Just repeating the same procedure, we can efficiently recover p at 2047 bit.<br>
