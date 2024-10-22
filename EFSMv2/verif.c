#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>

//#define IMPORT_ALL_RESULTS
#ifndef IMPORT_ALL_RESULTS
#define IMPORT_FINAL_RESULT
#endif


int main() {

    //reads the secret key from file
    FILE* secret_key = fopen("secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);
    //if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet* params = key->params;

	
	#ifdef IMPORT_ALL_RESULTS   //read and decrypt the 10 ciphertext of the result
    //read and decrypt the 7 ciphertext of the result
    LweSample* Answer_HE = new_gate_bootstrapping_ciphertext_array(7, params);
	uint8_t Answer_plain[7];
    FILE* Answer_file = fopen("out_file.data","rb");
    printf("The asnwer bits:");
	for(int i=0; i<7; i++)
	{
		import_gate_bootstrapping_ciphertext_fromFile(Answer_file, &Answer_HE[i], params);
		Answer_plain[i] = bootsSymDecrypt(&Answer_HE[i],key);
		printf(" %hhu",Answer_plain[i]);
		
	}
    fclose(Answer_file);


    //clean up all pointers
    delete_gate_bootstrapping_ciphertext_array(7, Answer_HE);

    #else
    LweSample* Answer_HE = new_gate_bootstrapping_ciphertext(params);
    uint8_t Answer_plain;
    FILE* Answer_file = fopen("final_out_file.data","rb");
    printf("The final asnwer bit:");
    import_gate_bootstrapping_ciphertext_fromFile(Answer_file, Answer_HE, params);
    Answer_plain = bootsSymDecrypt(Answer_HE,key);
    printf(" %hhu\n",Answer_plain);
    fclose(Answer_file);
    //clean up all pointers
    delete_gate_bootstrapping_ciphertext(Answer_HE);

    #endif


    delete_gate_bootstrapping_secret_keyset(key);

}
