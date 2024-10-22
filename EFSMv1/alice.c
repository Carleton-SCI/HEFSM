#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <time.h>


/*
- The fsm machine will be directly exported to the cloud. No need for the secure user to care about it.
- The fsm structure is clearly visisble to everyone at the cloud
- However, the input will be encoded by a table to HE bits. So the adversary won't be able to know the input value to the FSM
- Surely, the FSM is implemented in HE, so the states and output are covered.
- The purpose of the task of the script is to export the cloud keys and the HE-Encrypted encoding table
*/

int main() {
    //generate a keyset
    const int minimum_lambda = 110;
    TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    //generate a random key
    uint32_t seed[] = {314, 1592, 657};
    tfhe_random_generator_setSeed(seed,3);
    TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);
	
	//The fsm machine will be directly exported to the cloud. No need for the secure user to care about it
	
	uint8_t input_bits;    //Number of input bits = number of bits per encoded character - Maximum is 8
	
	printf("Reading, encrypting, and exporting the plain encoding table...\n");
	FILE* PCodeTable = fopen("PCodeTable.txt","rb");   //Read the integer plain encoding values from here
	FILE* HCodeTable = fopen("HCodeTable.data","wb");   //Export the HE encrypted binary encoded values to here
	fscanf(PCodeTable,"%hhu",&input_bits);            //First value in the Plaincode file is the number of input bits
	
	uint8_t pcode_value_int;
	LweSample *hcode_value_bit = new_gate_bootstrapping_ciphertext(params);
	
	
	time_t duration = 0;  //What is done below is to exclude the time used for saving to disk.
	for(int i=0; i<256; i++)
	{
		fscanf(PCodeTable,"%hhu",&pcode_value_int);   //Get the encoded integer
		for(int j=0; j<input_bits; j++)               //HE encrypt and export
		{
			time_t start = clock();
			bootsSymEncrypt(hcode_value_bit, (pcode_value_int >> j) & 1, key);
			duration += clock() - start;

			export_gate_bootstrapping_ciphertext_toFile(HCodeTable, hcode_value_bit, params);
		}
		
	}

	printf("Encryption time= %f secs\n", (duration)/1000000.0);
	


	fclose(PCodeTable);
	fclose(HCodeTable);
	printf("Done.\n");
	
	
    printf("Exproting keys to files for using at the cloud\n");
    //export the secret key to file for later use
    FILE* secret_key = fopen("secret.key","wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
    fclose(secret_key);

    //export the cloud key to a file (for the cloud)
    FILE* cloud_key = fopen("cloud.key","wb");
    export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
    fclose(cloud_key);

	
	
    //clean up all pointers
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);
	delete_gate_bootstrapping_ciphertext(hcode_value_bit);
	printf("Done! Good luck at the cloud side!\n");
}
