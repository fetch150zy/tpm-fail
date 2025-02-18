#!/bin/sh

# test tpmtools
tpm2_getcap properties-variable
tpm2_getcap properties-fixed | grep -A11 TPM2_PT_VENDOR_STRING_1
