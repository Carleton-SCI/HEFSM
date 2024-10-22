# Encrypted Finite State Machine v2 (EFSMv2)

The files in this folder provide proof-of-concept for the design and implementation of EFSMv2 for matching plaintext data against encrypted rules and producing encrypted results. The design and implementation details are available in:

*Mahmoud Sayed and Mostafa Taha, Evaluation of Encrypted Matching Criteria using Homomorphic Encryption-Based FSM, Journal of Cryptographic Engineering, 2024.*

The Regex -> Finite State Machine -> Sum Of Products processes are not automated for EFSMv2. Instead, the regex ".*A.(B|C)C.* is hard-coded into the testing procedure. An interested user can use the techniques in "Regex_to_SOP.py" file in EFSMv1 to convert a Regex to an FSM then to SOP, but they will have to rewrite these SOP expressions (and masking stream) into the EFSMv2 machine.

## Organization

The files here are:

1. **alice.c**: This C code generates the TFHE secret key and cloud key. It also encrypts the alphabet and the masking stream into files. The code depends on the `TFHE-io` library.  
2. **cloud.c**: This C code performs the encrypted matching task between the plaintext (defined in the file) and the encrypted rule represented by the encrypted FSM. It generates the result as a final bit serialized in an output file. The code depends on the `TFHE-io` library.  

3. **verif.c**: This C code performs decrypts the final result sent back from the cloud (as a file) using the private key and prints the result. The code depends on the `TFHE-io` library.  


## Steps

Please follow these steps to reproduce the results.

1. Make sure to update the environment variables as required by the TFHE-io library, by following the instructions in the TFHE-io README.md file. As a shortcut, you can use the source env_v.txt file (included in this folder) by:  
```bash
source env_v.txt
```

3. In the file `cloud.cpp` you can change the plaintext that will be matched against the encrypted rule specified by the regex defined in `Regex_to_SOP.py`  
Line 67: `char plainstream[20] = "AbfjmAQBCC" ;  //10 chars string`  

4. Compile the code files using:  
```bash
gcc alice.c -o alice.out -ltfhe-spqlios-fma  
gcc cloud.cpp -o cloud.out -ltfhe-spqlios-fma -lm  
gcc verif.c -o verif.out -ltfhe-spqlios-fma  
```
5. Execute and watch the output
```bash
./alice.out
./cloud.out
./verif.out
```

