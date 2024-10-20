# HEFSM
This repo provides a proof-of-concept for the design and implementation of Homomorphically Encrypted Finite State Machine (HEFSM) for matching plaintext data against encrypted rules and producing encrypted results. The design and implementation details are available in "Mahmoud Sayed and Mostafa Taha, Evaluation of Encrypted Matching Criteria using Homomorphic Encryption Based FSM, Jorunal of Cryptographic Engineering, 2024"
# Contents
This repo contains two implementations
1- EFSMv1: The first variation of the encrypted FSM provides a methodology of implementing any regular expression as an encrypted finite state machien, providing flixibility at the cost of less security compared to the other variant
2- EFSMv2: EFSMv2 provides more strict security compared to EFSMv1 in the expense of more restriction on the regular expression (accepted strings must of pre-defined length at the compilation time, thus regexes that accept strings with arbitrary lengths cannot be implemented, except for the case of .* (wild-card kleene start) at the beginning and the end of the expression).
# Prequisties
There are two main prequeistes: TFHE-io library as the Homomorphic Encryption (HE) engine, and Greenery library for converting regular expression into finite state machine
## TFHE-io Library
While the EFSMv1-2 are HE library independent (Can be implemented with any HE library that supports logic operations), the provided proof-of-concept is built upon TFHE-io library. Please follow the steps outlined in: https://tfhe.github.io/tfhe/ to install the TFHE-io library
## Greenery Library
EFSMv1 uses some of the mechanics in Greenery to convert regular expression into a minimized finite state machine, which is then implemented by the HE library. Our implementation uses a specific version of Greenery, **DO NOT INSTALL THE LATEST VERSION**. Instead, install version **3.3.1** which can be instealled by:  
`pip install greenery==3.3.1`



