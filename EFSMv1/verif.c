#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>

//#define IMPORT_ALL_RESULTS   //Works with "#define EXPORT_ALL_RESULTS" in cloud.c, read the output bit after processing each character in the input
#ifndef IMPORT_ALL_RESULTS
#define IMPORT_FINAL_RESULT// Works with "#define EXPORT_FINAL_RESULTS" in cloud.c, Read the final output only (exported once after processing all input)
#endif


int main() {

    //reads the secret key from file
    FILE* secret_key = fopen("secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);
    //if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet* params = key->params;

	
	
    
    #ifdef IMPORT_ALL_RESULTS   //read and decrypt the 10 ciphertext of the result
    LweSample* Answer_HE = new_gate_bootstrapping_ciphertext_array(10, params);
	uint8_t Answer_plain[10];
    FILE* Answer_file = fopen("out_file.data","rb");
    printf("The asnwer bits:");
	for(int i=0; i<10; i++)
	{
		import_gate_bootstrapping_ciphertext_fromFile(Answer_file, &Answer_HE[i], params);
		Answer_plain[i] = bootsSymDecrypt(&Answer_HE[i],key);
		printf(" %hhu",Answer_plain[i]);
		
	}
	printf("\n");
    fclose(Answer_file);
    //clean up all pointers
    delete_gate_bootstrapping_ciphertext_array(10, Answer_HE);
    #endif

    #ifdef IMPORT_FINAL_RESULT
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




    //clean up keys
    delete_gate_bootstrapping_secret_keyset(key);

}
