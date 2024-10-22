#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <time.h>
#include <math.h>
#include <stdlib.h>
#include "fsm_class.cpp"

//#define EXPORT_ALL_RESULTS      //To export the "output" bit (function of current state) after processing each character
#ifndef EXPORT_ALL_RESULTS
#define EXPORT_FINAL_RESULT//     To export the output onece time after processing all input characters
#endif
//typedef void(TFHE_not) (LweSample*, const LweSample*, const TFheGateBootstrappingCloudKeySet*)




//---------------------------------------Matching Functions------------------------------------------------------------------

int main() 
{
    FSM fsm;            //instance of the handmade fsm_class.cpp FSM class
	uint8_t ninputs;    //Number of input bits. Needed as the encoding table width 
	
	//--------------Read Basic cloud key and params---------------------
    //reads the cloud key from file
    FILE* cloud_key = fopen("cloud.key","rb");
    TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);
    //if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet* params = bk->params;
	//-------------------------------------------------------------------
	
	/*
	//DEBUGGINGDEBIGGING
	//reads the secret key from file
    FILE* secret_key = fopen("secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);
	*/
	
	
	//-----------Reading the fsm data from file----------------
	FILE* fsmfile = fopen("fsm.txt","rb");
	fsm.init_from_file(fsmfile, bk);
	fclose(fsmfile);
    printf("The read FSM:\n");
	fsm.show_fsm();
	printf("\n");
	//----------------------------------------------------------
	
	//----------Reading the encoding table----------------------
	ninputs = fsm.ninputs;
	LweSample** HCodeTable = new LweSample*[256];
	FILE* HCodeTablefile = fopen("HCodeTable.data","rb");
	for(int i=0; i<256; i++)
	{
		HCodeTable[i] = new_gate_bootstrapping_ciphertext_array(ninputs,params);
		for(int j=0; j<ninputs; j++)
			import_gate_bootstrapping_ciphertext_fromFile(HCodeTablefile, &HCodeTable[i][j], params);
	}
	fclose(HCodeTablefile);
	
	
	//-------The input plain searching string-------------
	printf("Creating the plainstream\n");
	char plainstream[20] = "AbfjmAQBCC" ;  //10 chars string 
	uint8_t plainstream_length = 10;
	printf("Plain stream created.\n");
	printf("Will be seraching through %s\n",plainstream);
	//----------------------------------------------------
	
	FILE* out_file = fopen("out_file.data","wb");
	

	#ifdef EXPORT_FINAL_RESULT
	FILE* final_out_file = fopen("final_out_file.data","wb");
	#endif



	time_t start_time = clock();
	//------Looping through the stream----------
	for(int i=0; i<plainstream_length; i++)
	{
		//printf("Processing char #%hhu of %hhu\n",i+1,plainstream_length);
		fsm.process_input(HCodeTable[plainstream[i]]);
		#ifdef EXPORT_ALL_RESULTS
		export_gate_bootstrapping_ciphertext_toFile(out_file, fsm.output, params);
		#endif

		/*DEBUGGINGDEBIGGING
		printf("Input Value: ");
		for(int j= fsm.ninputs-1; j>=0; j--)
		{
			uint8_t tempo = bootsSymDecrypt(&HCodeTable[ plainstream[i]][j] ,key);
			printf("%d ",tempo);
		}
		
		printf("    Current state: ");
		for(int j= fsm.nstates-1; j>=0; j--)
		{
			uint8_t tempo = bootsSymDecrypt(&fsm.states[j],key);
			printf("%d ",tempo);
		}
		printf("\n");
		*/
	
	}
	time_t end_time = clock();
	printf("Searching time= %f secs\n", (end_time-start_time)/1000000.0);
	
	#ifdef EXPORT_ALL_RESULTS
	fclose(out_file);
	#endif

	#ifdef EXPORT_FINAL_RESULT
	export_gate_bootstrapping_ciphertext_toFile(final_out_file, fsm.output, params);
	fclose(final_out_file);
	#endif
	
	//------Housekeeping---------
	for(int i=0; i<256; i++)
	{
		delete_gate_bootstrapping_ciphertext_array(ninputs, HCodeTable[i] );
	}
	delete HCodeTable;
	printf("Done! Good luck with the result !\n");
}




