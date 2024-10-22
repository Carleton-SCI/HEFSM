# Encrypted Finite State Machine v1 (EFSMv1)

The files in this folder provide a proof-of-concept for the design and implementation of a EFSMv1 for matching plaintext data against encrypted rules and producing encrypted results. The design and implementation details are available in:

*Mahmoud Sayed and Mostafa Taha, Evaluation of Encrypted Matching Criteria using Homomorphic Encryption-Based FSM, Journal of Cryptographic Engineering, 2024.*

## Organization

The files here are:

1. **Regex_to_SOP.py**: The first part of this python script converts a regular expression into its equivalent Finite State Machine as a state table. The second part realizes the state table as a minimized Sum Of Product (SOP) expressions. The script dependes on `Greenery(3.3.1)` and `logicming(0.4.0)` libraries for which the installtion instructions are provided in the repo's general README.MD  
2. **alice.c**: This C code generates the TFHE secret key and cloud key. It also encryptes the lookup table and serialize everything into file. The code depends on the `TFHE-io` library.  
3. **cloud.cpp**: This C++ code performs the encrypted matching task between the plaintext (defined in the file) and the encrypted rule represented by the encrypted FSM. It generates the result as a final bit serialized in an output file. The code depends on the `TFHE-io` library.  

4. **verif.c**: This C code performs decrypts the final result sent back from the cloud (as a file) using the private key and prints the result. The code depends on the `TFHE-io` library.  

5. **fsm_class.cpp**: C++ class for the FSM evaluation on the cloud. It's used by cloud.cpp. The code depends on the `TFHE-io` library.  
## Steps

Please follow these steps to reproduce the results.

1. Make sure to update the envrionment variables as required by the TFHE-io library, by following the instructions in the TFHE-io README.md file. As a shortcut, you can use the source env_v.txt file (included in this folder) by:  
```bash
source env_v.txt
```
2. In the file `Regex_to_SOP.py`, you can change the regular expression that represents the rule.
Line 14: `regex= lego.parse(".*A.(B|C)C.*") `  

3. In the file `cloud.cpp` you can change the plaintext that will be matched against the encrypted rule specified by the regex defined in `Regex_to_SOP.py`  
Line 67: `char plainstream[20] = "AbfjmAQBCC" ;  //10 chars string`  

4. Compile the code files using:  
```bash
gcc alice.c -o alice.out -ltfhe-spqlios-fma  
g++ cloud.cpp -o cloud.out -ltfhe-spqlios-fma  
gcc verif.c -o verif.out -ltfhe-spqlios-fma  
```
5. Execute and watch the output
```bash
python3 Regex_to_sop.py
./alice.out
./cloud.out
./verif.out
```
