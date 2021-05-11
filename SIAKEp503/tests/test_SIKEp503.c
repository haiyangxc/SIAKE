/********************************************************************************************
* Supersingular Isogeny Key Encapsulation Library
*
* Abstract: benchmarking/testing isogeny-based key encapsulation mechanism SIKEp503
*********************************************************************************************/ 

#include <stdio.h>
#include <string.h>
#include "test_extras.h"
#include "../P503/api.h"

#include "../sha3/fips202.h"


#define SCHEME_NAME    "SIAKEp503"


#include "test_sike.c"