#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <time.h>
#include <math.h>
#include <stdlib.h>


#define INVERTED 1
#define NOT_INVERTED 0
#define COMPLEX 1
#define NOT_COMPLEX 0

//#define EXPORT_ALL_RESULTS

#ifndef EXPORT_ALL_RESULTS
#define EXPORT_FINAL_RESULT
#endif

typedef void(TFHE_func)(LweSample*, const LweSample*, const LweSample*, const TFheGateBootstrappingCloudKeySet*);
//typedef void(TFHE_not) (LweSample*, const LweSample*, const TFheGateBootstrappingCloudKeySet*)




//---------------------------------------Matching Functions------------------------------------------------------------------
/*Bitwise XORing a plain character with 8 HE key bits and results in 8 HE bits*/
void Hybrid_char_encryption(char plain_char, const LweSample* cover_key, LweSample* encrypted_result, const TFheGateBootstrappingCloudKeySet* bk, const TFheGateBootstrappingParameterSet* params);

/*Bitise XNOR between two HE chars, ANDing the resultant bits into a single result answer bit */
void HE_char_matching(const LweSample* char1, const LweSample* char2, LweSample* result, const TFheGateBootstrappingCloudKeySet* bk, const TFheGateBootstrappingParameterSet* params);

/*Generic n-input gate. Pass the inputs in array. pass the gate function. specificy if the final output is inverted (to calculate NOR, pass OR and tell that the output is inverted
iscomplex can be used to specify if some of the inputs need to be inverted (to calculate AB'C'D for example). In this case, pass 1 for iscomplex and pass an array of 0's and 1's
to the invarray. 1 means input will be inverted. Ex. (A,B,C,D) (Pass And gate) (Final not inverted) (iscomplex = 1) (invarray= [0 1 1 0]) will calculate AB'C'D
*/
void HE_func_narrinput(const LweSample* arr, LweSample* result, uint8_t n,
						uint8_t isinverted, uint8_t iscomplex, uint8_t *invarray,
					   TFHE_func Tfunc,
					   const TFheGateBootstrappingCloudKeySet* bk, const TFheGateBootstrappingParameterSet* params);

//Dynamic size HE binary encoder. Pass input & output arrays and alphabet length and it will calculate the required output width & values
void HE_Encoder(const LweSample* input, LweSample* output,const uint8_t alphabet_len, const TFheGateBootstrappingCloudKeySet* bk, const TFheGateBootstrappingParameterSet* params);

//A non-generic FSM :(
void FSM(LweSample* states, const LweSample* input, LweSample* output, uint8_t calc_output, const TFheGateBootstrappingCloudKeySet* bk, const TFheGateBootstrappingParameterSet* params);


int main() 
{
    uint8_t Alphabet_length;      // Number of characters in the alphabet
	uint8_t Alphabet_bitwidth;    // Log2(Alphabet_length)
	uint8_t Regex_length;	      // Regex Length !
	uint8_t States_bitwidth = 3;  // log2(number of states required for the fsm)(previously designed and calculated, not here)
	
	
    printf("reading the key...\n");
	//--------------Read Basic cloud key and params---------------------
    //reads the cloud key from file
    FILE* cloud_key = fopen("cloud.key","rb");
    TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);
    //if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet* params = bk->params;
	//-------------------------------------------------------------------
	
	
	
	
	//--------Reading Regx size, alphabet size, and alphabet bitwidth------------------------
	//Import the alphabet size
	FILE* alphabet_length_file = fopen("alphabet_length.data","rb");
	fscanf(alphabet_length_file,"%hhu", &Alphabet_length);
	fclose(alphabet_length_file);
	Alphabet_bitwidth = ceil(log(Alphabet_length+1)/log(2));
	
	//Import the regex length
	FILE* regex_length_file = fopen("regex_length.data","rb");
	fscanf(regex_length_file,"%hhu", &Regex_length);
	fclose(regex_length_file);
	
	printf("Regex length = %hhu, Alphabet Length = %hhu, Alphabet Bitwidth = %hhu\n", Regex_length , Alphabet_length, Alphabet_bitwidth);
	
	//------------------------------------------------------------------
	
	
	
	//--------Reading the coverkey-------------------------
	printf("Reading Cover Key\n");
	FILE* cover_key_file = fopen("HE_coverkey.key","rb");
	LweSample** Coverkey = (LweSample**) malloc(Regex_length*sizeof(LweSample*));
	for(int i=0; i<Regex_length; i++)
	{
		Coverkey[i] = new_gate_bootstrapping_ciphertext_array(8, params);
		for(int j=0; j<8; j++)
			import_gate_bootstrapping_ciphertext_fromFile(cover_key_file, &Coverkey[i][j], params);
	}
	fclose(cover_key_file);
	//------------------------------------------------------
	
	
	
	//--------Reading the HE covered alphabet---------------
	printf("Reading Covered alphabet\n");
	LweSample** Alphabet = (LweSample**) malloc(Alphabet_length*sizeof(LweSample*));
	for(int i=0; i<Alphabet_length; i++)
	{
		Alphabet[i] = new_gate_bootstrapping_ciphertext_array(8, params);
		char fname[30];
		sprintf(fname,"HE_Regex_Alphabet_%u.data",i);
		FILE* alphabet_char_file = fopen(fname,"rb");
		for(int j=0; j<8; j++)
			import_gate_bootstrapping_ciphertext_fromFile(alphabet_char_file, &Alphabet[i][j], params);
		fclose(alphabet_char_file);
	}
	//-------------------------------------------------------
	
	
	
	
	//--------Reading the HE zero----------------------------
	printf("Reading HE Zero\n");
	LweSample* HE_zero = new_gate_bootstrapping_ciphertext(params);
	FILE* HE_zero_file = fopen("HE_zero.data","rb");
	import_gate_bootstrapping_ciphertext_fromFile(HE_zero_file, HE_zero, params);
	fclose(HE_zero_file);
	//--------------------------------------------------------
	
	
	
	
	//-------The input plain searching string-------------
	printf("Creating the plainstream\n");
	char plainstream[20] = "KKLNKQMNLL" ;  //10 chars string - there are two matches starting from positions 0 and 4 (count from 0)
	uint8_t plainstream_length = 10;
	printf("%hhu\n",plainstream_length-Regex_length+1);
	printf("Plain stream created.\n");
	printf("Will be seraching through %s",plainstream);
	//----------------------------------------------------
	printf("%hhu\n",plainstream_length-Regex_length+1);

	//----The output status array (The only important output to be exported) and output file---
	printf("Creating status array\n");
	
	LweSample* Output_array = new_gate_bootstrapping_ciphertext_array(plainstream_length-Regex_length+1, params);
	printf("Output status array created.\n");
	
	#ifdef EXPORT_ALL_RESULTS
	FILE* out_file = fopen("out_file.data","wb");
	#else
	FILE* out_file = fopen("final_out_file.data","wb");
	#endif
	
	//States bits, size = States_bitwidth bits (3 bits) (States bits are reinialized at each block)
	printf("Creating states bits with  width = %hhu\n",States_bitwidth);
	LweSample* States_bits = new_gate_bootstrapping_ciphertext_array(States_bitwidth, params);
	printf("States bits with width = %hhu created.\n",States_bitwidth);
	
	//------------Dividing the stream into blocks---------------------
	//Blocks through stream loop
	printf("We will loop for %hhu times\n",plainstream_length-Regex_length+1);
	
	time_t start_time = clock(); //Start time of computation
	for(int i=0; i<=plainstream_length-Regex_length; i++)
	{
		printf("Processing block %u from %d\n", i+1 , plainstream_length-Regex_length+1);
		//initializing states to zeros (Reinitialized at each block)
		for(int i=0; i< States_bitwidth; i++)
			bootsCOPY(&States_bits[i],HE_zero,bk);
		
		//Chars through block loop
		for(int j=0; j< Regex_length; j++)
		{
			//-----Constructing vectors-----------------
			//Construct an 8 bit encrypted byte column
			LweSample* Encrypted_char = new_gate_bootstrapping_ciphertext_array(8, params);
			
			//Construct (alphabet_length+1) Matching column for byte j in the block
			LweSample* Matching_col = new_gate_bootstrapping_ciphertext_array(Alphabet_length+1, params);
			
			
			//Construct Encoder output column for byte j in the block
			LweSample* Encoded_col = new_gate_bootstrapping_ciphertext_array(Alphabet_bitwidth, params);
			
			//---------------------------------------------
			
			
			//-------------Preparing input bits to the FSM---------------
			//Encrypte an 8 bit plain letter j from the block i into the created space (hybrid xor with the cover key)
			Hybrid_char_encryption(plainstream[i+j], Coverkey[j], Encrypted_char,  bk,  params);
			
			//Filling column j in the matching matrix (for letter j in the block i)
			for(int k=Alphabet_length; k>0; k--)
			{
				HE_char_matching(Encrypted_char , Alphabet[k-1], &Matching_col[k], bk,  params);
			}
			HE_func_narrinput(&Matching_col[1],&Matching_col[0],Alphabet_length, INVERTED, NOT_COMPLEX, NULL, bootsOR, bk, params);
			
			//Encoding the matching matrix column calculated above
			HE_Encoder(Matching_col, Encoded_col, Alphabet_length, bk, params);
			//-----------------------------------------------------------
			
			
			//----------Feeding the fsm and generating output------------
			if(j == Regex_length - 1)  //The output should be updated only at the end of the block
				FSM(States_bits, Encoded_col, &Output_array[i],1, bk, params);
			else
				FSM(States_bits, Encoded_col, &Output_array[i],0, bk, params);
			
			
			//----------Housekeeping (columns)----------
			delete_gate_bootstrapping_ciphertext_array(8,Encrypted_char);
			delete_gate_bootstrapping_ciphertext_array(Alphabet_length+1,Matching_col);
			delete_gate_bootstrapping_ciphertext_array(Alphabet_bitwidth, Encoded_col);
		}
		
		//-----Writing the output to output file
		#ifdef EXPORT_ALL_RESULTS
		export_gate_bootstrapping_ciphertext_toFile(out_file, &Output_array[i], params);
		#else
		if(i > 0)
			bootsOR(&Output_array[0],&Output_array[0],&Output_array[i],bk);
		#endif
	}
	time_t end_time = clock();
	printf("Searching time= %f secs\n", (end_time-start_time)/1000000.0);
	
	#ifndef EXPORT_ALL_RESULTS
	export_gate_bootstrapping_ciphertext_toFile(out_file, &Output_array[0], params);
	#endif

	
	

	printf("After the for loop");
	//------Housekeeping (output array)(cover key)(alphabet)(HE_zero)(States)---------
	
	fclose(out_file);
	
	
	delete_gate_bootstrapping_ciphertext_array(plainstream_length-Regex_length+1,Output_array);
	delete_gate_bootstrapping_ciphertext_array(States_bitwidth,States_bits);
    delete_gate_bootstrapping_cloud_keyset(bk);
	delete_gate_bootstrapping_ciphertext(HE_zero);
	
	for(int i=0; i<Regex_length; i++)
		delete_gate_bootstrapping_ciphertext_array(8,Coverkey[i]);
	free(Coverkey);
	
	for(int i=0; i<Alphabet_length; i++)
		delete_gate_bootstrapping_ciphertext_array(8, Alphabet[i]);
	free(Alphabet);
}


void Hybrid_char_encryption(char plain_char, const LweSample* cover_key, LweSample* encrypted_result, const TFheGateBootstrappingCloudKeySet* bk, const TFheGateBootstrappingParameterSet* params)
{
	for(int i=0; i<8; i++)
	{
		//The encryption is a hybrid xor
		if(  (plain_char>>i)&1)
			bootsNOT(&encrypted_result[i], &cover_key[i], bk); /** bootstrapped Not Gate: result = not(coverkey[i]) */ 
		else
			bootsCOPY(&encrypted_result[i], &cover_key[i], bk); /** bootstrapped Copy Gate: result = coverkey[i] */
	}
}



void HE_char_matching(const LweSample* char1, const LweSample* char2, LweSample* result, const TFheGateBootstrappingCloudKeySet* bk, const TFheGateBootstrappingParameterSet* params)
{
	LweSample* result_bit  = new_gate_bootstrapping_ciphertext_array(8, params);
	for (int i=0; i<8; i++)
	{
		bootsXNOR(&result_bit[i], &char1[i], &char2[i], bk);
	}
	
	HE_func_narrinput(result_bit, result, 8 , NOT_INVERTED , NOT_COMPLEX, NULL, bootsAND, bk, params);
	/*
	bootsAND(result, &result_bit[0], &result_bit[1], bk);
	for(int i=2; i<8; i++)
	{
		bootsAND(result, result, &result_bit[i], bk);
    }
	*/
    delete_gate_bootstrapping_ciphertext_array(8, result_bit);
	
}

void HE_func_narrinput(const LweSample* arr, LweSample* result, uint8_t n, uint8_t isinverted,
						uint8_t iscomplex, uint8_t *invarray,
					   TFHE_func Tfunc,
					   const TFheGateBootstrappingCloudKeySet* bk, const TFheGateBootstrappingParameterSet* params)
{
	//If there is an inverting array (To evaluate something like wx'y'z the inverting araay should be [0 1 1 0]
	if(iscomplex)
	{
		LweSample* temp_bit  = new_gate_bootstrapping_ciphertext(params);
		if (invarray[0] == 1)
			bootsNOT(result,&arr[0],bk);
		else
			bootsCOPY(result,&arr[0],bk);
		for(int i=1; i<n; i++)
		{
			if(invarray[i] == 1)
			{
				bootsNOT(temp_bit,&arr[i],bk);
				Tfunc(result,result,temp_bit,bk);
			}
			else
				Tfunc(result,result,&arr[i],bk);
		}
		delete_gate_bootstrapping_ciphertext(temp_bit);	
	}
	else
	{
		Tfunc(result, &arr[0], &arr[1], bk);
		for (int i=2; i<n; i++)
			Tfunc(result,result,&arr[i],bk);
	}
	if(isinverted)
		bootsNOT(result,result,bk);
}

void HE_Encoder(const LweSample* input, LweSample* output,const uint8_t alphabet_len, const TFheGateBootstrappingCloudKeySet* bk, const TFheGateBootstrappingParameterSet* params)
{
	uint8_t output_len = (uint8_t)ceil(log(alphabet_len+1)/log(2));
	/* The methodology is implemented the following
	Q0 = ___ +I1 ___ +I3 ___ +I5 ___ +I7 ___ ....
	Q1 = ___ ___ +I2 +I3 ___ ___ +I6 +I7 ___ ....
	Q2 = ___ ___ ___ ___ +I4 +I5 +I6 +I7 ___ ....
	*/
	//Looping through output variables
	for(int i=0; i<output_len; i++)
	{
		uint8_t elements = pow(2,i);    // Number of successive elements per step
		uint8_t step = elements*2;      // Step width
		//Looping through the input variables with suitable step
		bootsCOPY(&output[i],&input[elements],bk);     //assigning first element manually
		for(int j=elements; j<alphabet_len+1; j+=step)
			for(int k=j; k<j+elements && k<alphabet_len +1; k++)
			{
				if (k == elements) //skip first input only, already assigned few lines ago
					continue;
				bootsOR(&output[i],&output[i],&input[k],bk);
			}
	}

}

void FSM(LweSample* states, const LweSample* input, LweSample* output, uint8_t calc_output, const TFheGateBootstrappingCloudKeySet* bk, const TFheGateBootstrappingParameterSet* params)
{
	LweSample* next_states = new_gate_bootstrapping_ciphertext_array(3,params);
	LweSample* temp1 = new_gate_bootstrapping_ciphertext(params);
	LweSample* temp2 = new_gate_bootstrapping_ciphertext(params);
	
	LweSample* temp_arr = new_gate_bootstrapping_ciphertext_array(4,params);
	bootsCOPY(&temp_arr[0], &states[1], bk);
	bootsCOPY(&temp_arr[1], &states[0], bk);
	bootsCOPY(&temp_arr[2], &input[1], bk);
	bootsCOPY(&temp_arr[3], &input[0], bk);
	
	
	
	uint8_t invarr[4];
	
	//Calculating next S2------
	HE_func_narrinput(temp_arr, &next_states[2], 4,
					   NOT_INVERTED, NOT_COMPLEX, NULL,
					   bootsAND,
					   bk, params
					   );
	//------------------------
	
	
	//Calculating next s1-----
	invarr[0]   = 0 ;	   	   invarr[1] = 1;          invarr[2] = 0;
	HE_func_narrinput(temp_arr, temp1, 3,
					   NOT_INVERTED, COMPLEX, invarr,
					   bootsAND,
					   bk, params
					   );
	
	
	invarr[0]   = 1 ;	   	   invarr[1] = 0;         	
	HE_func_narrinput(temp_arr, temp2, 2,
					   NOT_INVERTED, COMPLEX, invarr,
					   bootsAND,
					   bk, params
					   );
	bootsOR(&next_states[1],temp1,temp2,bk);
	//-------------------------
	
	//Calculating next S0------
	invarr[0]   = 1 ;	   	   invarr[1] = 1;          invarr[2] = 1;          invarr[3] = 0;
	HE_func_narrinput(temp_arr, temp1, 4,
					   NOT_INVERTED, COMPLEX, invarr,
					   bootsAND,
					   bk, params
					   );
					   

	invarr[0]   = 0 ;	   	   invarr[1] = 1;          invarr[2] = 0;         
	HE_func_narrinput(temp_arr, temp2, 3,
					   NOT_INVERTED, COMPLEX, invarr,
					   bootsAND,
					   bk, params
					   );
	bootsOR(&next_states[0],temp1,temp2,bk);
	//-------------------------
	
	//----Calculating output---
	if(calc_output)
		bootsCOPY(output,&next_states[2],bk);
	//-------------------------
	
	//----Setting "new" current states
	for(int i=0; i<3; i++)
	{
		bootsCOPY(&states[i],&next_states[i],bk);
	}
	
	//---------Housekeeping---------
	delete_gate_bootstrapping_ciphertext_array(3, next_states);
	delete_gate_bootstrapping_ciphertext_array(4, temp_arr);
	delete_gate_bootstrapping_ciphertext(temp1);
	delete_gate_bootstrapping_ciphertext(temp2);
}

