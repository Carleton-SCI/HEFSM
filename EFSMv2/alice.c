#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>

#define cover_key_length  4   //length is equal to the regex length (Bytes) pre-processor to avoid problems with arrays initialization
#define Alphabet_length   3   //This is the alphabet size (Number of "different" chars in the regex
int main() {
    //generate a keyset
    const int minimum_lambda = 110;
    TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    //generate a random key
    uint32_t seed[] = {314, 1592, 657};
    tfhe_random_generator_setSeed(seed,3);
    TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);
	
	//Will be searching for the regex K.(L|M)N
	//The encryption-covering key will be 0xab630e0d
	
	uint8_t Plain_cover_key[cover_key_length] = {0xab, 0x63, 0x0e, 0x0d};
	//So the resultant encrypted seraching regex is the XOR between the original regex and the key=0x e0 . (42|43)43
	//Note that there are 3 different bytes only in the encrypted regex
	//Note that the regex length is the same as the cover key length which is 4 here
    
	uint8_t Plain_encrypted_alphabet[Alphabet_length] = {0xe0, 0x42, 0x43};
	
	printf("This is a regex searching expirement using TFHE.\n the regex has fixed legnth and the input stream must be handled block by\nblock with the same length. each block is separated by one char\n");
	printf("We will be seraching for the regex K.(L|M)N");
	printf("The plain encryption key is: 0x");
	for (int i =0; i<cover_key_length; i++)
	{
		printf("%02x ",Plain_cover_key[i]);
	}
	printf("\nSo, the encrypted alphabet is in the form of: 0x ");
	for (int i =0; i<Alphabet_length; i++)
	{
		printf("%02x ",Plain_encrypted_alphabet[i]);
	}
	
	//HE covering the key
	printf("\nHE Covering the the encryption key for block encryption of the stream at the cloud...\n");
	LweSample* HE_cover_key = new_gate_bootstrapping_ciphertext_array(8*cover_key_length, params);
	for (int i=0; i<cover_key_length; i++) 
    {
        for (int j=0; j<8; j++)
		bootsSymEncrypt(&HE_cover_key[i*8 + j], (Plain_cover_key[i]>>j)&1, key);
    }
	
	printf("HE Covering the encrypted regex letters for matching encoder at the cloud...\n");
	//HE covered regex letters (For the chars encoder at the cloud)
	LweSample* HE_encrypted_alphabet = new_gate_bootstrapping_ciphertext_array(8*Alphabet_length, params);
	for (int i=0; i<Alphabet_length; i++) 
    {
        for (int j=0; j<8; j++)
		bootsSymEncrypt(&HE_encrypted_alphabet[i*8 + j], (Plain_encrypted_alphabet[i]>>j)&1, key);
    }
	
	printf("Provding an HE zero for initialization of the fsm at the cloud...\n");
	//Providing an HE zero for initialization
	LweSample* HE_zero = new_gate_bootstrapping_ciphertext(params);
	bootsSymEncrypt(HE_zero, 0, key);
	
    
    printf("Exproting everything to files for using at the cloud\n");
    //export the secret key to file for later use
    FILE* secret_key = fopen("secret.key","wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
    fclose(secret_key);

    //export the cloud key to a file (for the cloud)
    FILE* cloud_key = fopen("cloud.key","wb");
    export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
    fclose(cloud_key);

    //exprot the HE covered encryption key
	FILE* HE_coverkey = fopen("HE_coverkey.key","wb");
	for (int i=0; i<8*cover_key_length; i++) 
        export_gate_bootstrapping_ciphertext_toFile(HE_coverkey, &HE_cover_key[i], params);
	fclose(HE_coverkey);
	
	
	//export the HE covered encrypted regex letters
	for (int i =0; i<Alphabet_length; i++)
	{
		char fname[25];
		sprintf(fname,"HE_Regex_Alphabet_%u.data",i);
		FILE* regex_byte = fopen(fname,"wb");
		for(int j =0; j<8; j++)
		{
			export_gate_bootstrapping_ciphertext_toFile(regex_byte, &HE_encrypted_alphabet[i*8 + j], params);
		}
		fclose(regex_byte);
	}
	
	//exprot the HE zero
	FILE* HE_zerof = fopen("HE_zero.data","wb");
    export_gate_bootstrapping_ciphertext_toFile(HE_zerof, HE_zero, params);
	fclose(HE_zerof);
	
	//Export the alphabet size
	FILE* alphabet_length = fopen("alphabet_length.data","wb");
	fprintf(alphabet_length,"%u",Alphabet_length);
	fclose(alphabet_length);
	
	//Export the regex length
	FILE* regex_length = fopen("regex_length.data","wb");
	fprintf(regex_length,"%u",cover_key_length);
	fclose(regex_length);
	
	
    //clean up all pointers
    delete_gate_bootstrapping_ciphertext_array(8*cover_key_length, HE_cover_key);
	delete_gate_bootstrapping_ciphertext_array(8*Alphabet_length, HE_encrypted_alphabet);
	delete_gate_bootstrapping_ciphertext(HE_zero);
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);
	printf("Done! Good luck at the cloud side!");
}
