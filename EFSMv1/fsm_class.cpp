#include <stdint.h>

#define INVERTED 1
#define NOT_INVERTED 0
#define COMPLEX 1
#define NOT_COMPLEX 0
#define INTERMITTENT 1
#define NOT_INTERMITTENT 0

typedef void(TFHE_func)(LweSample*, const LweSample*, const LweSample*, const TFheGateBootstrappingCloudKeySet*);

struct SOP_item
{
    uint8_t nterms;       //Number of product terms
    uint8_t nletters  ;   //Number of letters
    uint8_t **existance;  //Existance arrays. An array of nletters bits per product term  1: The letter exists. 0: The letter doesn't exist
    uint8_t **invert;     //Invert arrays.    An array of nletters bits per product term. 1: The letter is inverted. 0: letter is not inverted.
};

class FSM
{
    public:
    uint8_t nstates;  //Number of states bits (Number of D flip flops)
    uint8_t ninputs;  //Number of Input bits (Number of input lines)
    uint8_t noutputs; //Number of outputs
    
    LweSample* states;   //states bits //With length of nstates
    LweSample* output;   //output bit  //With length of noutputs
    
	const TFheGateBootstrappingCloudKeySet* bk; 		//TFHE Public key
	const TFheGateBootstrappingParameterSet* params;	//TFHE Encryption paramters
	
    SOP_item *Sequations;
    SOP_item *Oequations;
    
	~FSM()
	{
		delete_gate_bootstrapping_ciphertext_array(nstates, states);
		delete_gate_bootstrapping_ciphertext_array(noutputs,output);
		for(int i=0; i<nstates; i++)
		{
			for(int j=0; j<Sequations[i].nterms; j++)
			{
				delete Sequations[i].existance[j];
				delete Sequations[i].invert[j];
			}
			delete Sequations[i].existance;
			delete Sequations[i].invert;
		}
		delete Sequations;
		
		for(int i=0; i<noutputs; i++)
		{
			for(int j=0; j<Oequations[i].nterms; j++)
			{
				delete Oequations[i].existance[j];
				delete Oequations[i].invert[j];
			}
			delete Oequations[i].existance;
			delete Oequations[i].invert;
		}
		delete Oequations;
	}
	
    void init_from_file(FILE *fsmfile, const TFheGateBootstrappingCloudKeySet* bkk)
    {
        bk = bkk;
		params = bk->params;
        
        fscanf(fsmfile,"%hhu",&nstates);
        fscanf(fsmfile,"%hhu",&ninputs);
        fscanf(fsmfile,"%hhu",&noutputs);
        
        Sequations = new SOP_item[nstates];
        Oequations = new SOP_item[noutputs];
        states     = new_gate_bootstrapping_ciphertext_array(nstates, params);
        output     = new_gate_bootstrapping_ciphertext_array(noutputs, params);
		
        
        for(int i=0; i<noutputs; i++)        //Filling the outputs equations
            {
                fill_SOP_item_from_file(fsmfile, &Oequations[i], ninputs+nstates);
                bootsCONSTANT(output, 0, bk);
            }
        
        for(int i=0; i<nstates; i++)         //Filling the next states equations
            {
                fill_SOP_item_from_file(fsmfile, &Sequations[i], ninputs+nstates);
                bootsCONSTANT(&states[i], 0, bk);
            }
        
    }
    
    void show_fsm()
    {
        printf("Number of states bits: %d\n",nstates);
        printf("Number of input bits: %d\n",ninputs);
        printf("Number of outputs: %d\n",noutputs);
        
        printf("Output equations:\n");
        for(int i=0; i<noutputs; i++)
        {
            printf("O%hhu\n",i);
            printf("Existance:");
            for(int j=0; j<Oequations[i].nterms; j++)
            {
                printf("[ ");
                for(int k=Oequations[i].nletters-1; k>=0; k--)
                    printf("%d ",Oequations[i].existance[j][k]);
                printf("]");
            }
            
            printf("\nInvert   :");
            for(int j=0; j<Oequations[i].nterms; j++)
            {
                printf("[ ");
                for(int k=Oequations[i].nletters-1; k>=0; k--)
                    printf("%d ",Oequations[i].invert[j][k]);
                printf("]");
            }
        }
        
        printf("\nStates equations:");
        for(int i=0; i<nstates; i++)
        {
            printf("\nS%hhu\n",i);
            printf("Existance:");
            for(int j=0; j<Sequations[i].nterms; j++)
            {
                printf("[ ");
                for(int k=Sequations[i].nletters-1; k>=0; k--)
                    printf("%d ",Sequations[i].existance[j][k]);
                printf("]");
            }
            
            printf("\nInvert   :");
            for(int j=0; j<Sequations[i].nterms; j++)
            {
                printf("[ ");
                for(int k=Sequations[i].nletters-1; k>=0; k--)
                    printf("%d ",Sequations[i].invert[j][k]);
                printf("]");
            }
        }
        printf("\n");
    }
    
	void process_input(const LweSample* input)
	{
		LweSample* fsmfeed = new_gate_bootstrapping_ciphertext_array(nstates+ninputs,params);    // Fsm feed array: [Ik-1 .... I0 Sn-1 ....s0]
		for(int i=0; i<nstates; i++)				  //Filling with the current states bits (first part of fsm feed)
			bootsCOPY(&fsmfeed[i], &states[i], bk);
		
		for(int i=nstates; i<nstates+ninputs; i++)   //Filling with the input bits (second part of fsmfeed)
			bootsCOPY(&fsmfeed[i], &input[i-nstates], bk);
		
		
		LweSample* tembit = new_gate_bootstrapping_ciphertext(params);
		for (int i=0; i<nstates; i++)				  //Looping on next states
		{
			bootsCONSTANT(&states[i],0,bk);			  // The equation is in the form of ((SUM))-of-products. An intial zero value will do no harm
			for(int j=0; j<Sequations[i].nterms; j++) //Looping on the terms in each state
			{
				HE_func_narrinput(fsmfeed, tembit, Sequations[i].nletters, NOT_INVERTED,
						   INTERMITTENT,  Sequations[i].existance[j],
						   COMPLEX,       Sequations[i].invert[j],
						   bootsAND
						   );
				bootsOR(&states[i], &states[i], tembit, bk);
			}
		}
		
		//-----Calculation of the output based on the updated states -> update fsmfeed
		for(int i=0; i<nstates; i++)				     //Filling fsmfeed with the updated states bits (first part of fsm feed)
			bootsCOPY(&fsmfeed[i], &states[i], bk);
		//Note that the output logically should depend on the states only, not in the input
		for(int i=0; i<noutputs; i++)
		{
			bootsCONSTANT(&output[i],0,bk);
			for(int j=0; j<Oequations[i].nterms; j++)
			{
				HE_func_narrinput(fsmfeed, tembit, Oequations[i].nletters, NOT_INVERTED,
						   INTERMITTENT,  Oequations[i].existance[j],
						   COMPLEX,       Oequations[i].invert[j],
						   bootsAND
						   );
				bootsOR(&output[i], &output[i], tembit, bk);
			}
		}
		delete_gate_bootstrapping_ciphertext_array(nstates+ninputs, fsmfeed);
		delete_gate_bootstrapping_ciphertext(tembit);
	}
	
    private:
    void fill_SOP_item_from_file(FILE *fsmfile, SOP_item *item, uint8_t nletters)
    {
        item->nletters = nletters;
        fscanf(fsmfile,"%hhu",&item->nterms);
        item->existance = new uint8_t*[item->nterms];
        item->invert    = new uint8_t*[item->nterms];
        for(int i=0; i<item->nterms; i++)
        {
            uint8_t t,f;
            fscanf(fsmfile,"%hhu",&t);
            fscanf(fsmfile,"%hhu",&f);
            
            item->existance[i] = new uint8_t[item->nletters];
            item->invert[i]    = new uint8_t[item->nletters];
            
            for(int j=0; j<item->nletters; j++)
            {
                if(  ((t>>j)&1)  &&  !((f>>j)&1)    )    //exists and not inverted
                {
                    item->existance[i][j] = 1;
                    item->invert[i][j]    = 0;
                }
                else if( !((t>>j)&1)  &&  ((f>>j)&1)  ) //exist and inverted
                {
                    item->existance[i][j] = 1;
                    item->invert[i][j]    = 1;
                }
                else                                    //doesn't exist
                {
                    item->existance[i][j] = 0;
                    item->invert[i][j] = 0; //no meaning, but 0 is placed to avoid any bizzare behavior
                }
            }//end for of letters per product
        }//end for product terms per SOP item
    }//end function fill_SOP_item_from_file
    
	/*Generic n-input gate. Pass the inputs in array. pass the gate function. specificy if the final output is inverted (to calculate NOR, pass OR and tell that the output is inverted
	iscomplex can be used to specify if some of the inputs need to be inverted (to calculate AB'C'D for example). In this case, pass 1 for iscomplex and pass an array of 0's and 1's
	to the invarray. 1 means input will be inverted. Ex. (A,B,C,D) (Pass And gate) (Final not inverted) (iscomplex = 1) (invarray= [0 1 1 0]) will calculate AB'C'D
	intermittent is used to define if all the inputs in the array will be processed (intermittent=0) or only a specific portion specified by 1's in the existancearr
	*/
	void HE_func_narrinput(const LweSample* arr, LweSample* result, uint8_t n, uint8_t isinverted,
						   uint8_t intermittent,  uint8_t *existancearr,
						   uint8_t iscomplex,    uint8_t *invarray,
						   TFHE_func Tfunc
						   )
	{
		//If there is an inverting array (To evaluate something like wx'y'z the inverting araay should be [0 1 1 0]
		//If not, creat an all-uninverted invert array(all 0s)
		if(!iscomplex)
		{
			invarray = new uint8_t[n];
			for(int i =0; i<n; i++)
				invarray[i] = 0;		//all not inverted
		}
		
		//if the term is not intermittent, creat an all-exist existancearr (all 1s)
		if(!intermittent)
		{
			existancearr = new uint8_t[n];
			for(int i =0; i<n; i++)
				existancearr[i] = 1;	//all exist
		}
		
		uint8_t first_bit = 1;
		LweSample* temp_bit  = new_gate_bootstrapping_ciphertext(params);
		
		for(int i=0; i<n; i++)
		{
			if(existancearr[i] == 1)
			{
				if(first_bit)
				{
					if(invarray[i] == 1)
						bootsNOT(result,&arr[i],bk);
					else
						bootsCOPY(result, &arr[i], bk);
					first_bit = 0;
					continue;
				}
				
				if(invarray[i] == 1)
				{
					bootsNOT(temp_bit,&arr[i],bk);
					Tfunc(result,result,temp_bit,bk);
				}
				else
					Tfunc(result,result,&arr[i],bk);
				
			}
		}
		if(isinverted)
			bootsNOT(result,result,bk);
		
		delete_gate_bootstrapping_ciphertext(temp_bit);
		if(!iscomplex)
			delete invarray;
		if(!intermittent)
			delete existancearr;
	}
    
};