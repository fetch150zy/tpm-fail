## TPM_FAIL

> For Kernel v6.8.0

```bash
sh tpm2-setup.sh
cd x86 # or cd riscv
cd workspace && sh setup-kernel.sh
cd ECDSATPMKey && sh gen_tpm.sh
# or
cd ECDSATPMKey && sh gen_openssl.sh
seq 1000 | xargs -I -- sh run.sh
cat result.csv
```
