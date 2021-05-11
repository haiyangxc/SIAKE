# SIAKE

### Supersingular Isogeny based Authenticated Key Exchange
SIAKE is an authenticated key exchange based on supersingular isogenies. 
It is an implimentation of SIAKE_2 in [XXW+19]

[XXW+19] Xiu Xu, Haiyang Xue, Kunpeng Wang, Man Ho Au, Song Tian: Strongly Secure Authenticated Key Exchange from Supersingular Isogenies. ASIACRYPT (1) 2019: 278-308.
https://eprint.iacr.org/2018/760

### The unauthenticated key exchange is based on that in Supersingular Isogeny Key Encapsulation software
https://sike.org/#implementation

We use parameter from SIKE(https://sike.org/), a third round candidate of NIST post-quantum cryptography standardization.


### QUICK INSTRUCTIONS:

<SIAKEp#> refers to any of {SIAKEp434, SIAKEp503, SIAKEp610, SIAKEp751}.

Pick a given scheme, and then do:

$ cd <SIAKEp#>
$ make clean
$ make

Testing and benchmarking results are obtained by running:

$ ./sike/test_AKE
