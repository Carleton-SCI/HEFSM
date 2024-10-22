from greenery import lego
from greenery import fsm
import logicmin
import math
import os
from collections import OrderedDict

#Sorting key to ensure "anything_else" would be sorted last
def msort(sym):
    #return(type(sym[0])!=str,str(sym[0]))
    return (sym is fsm.anything_else, str(sym))

#Parsing the input regex
regex= lego.parse(".*A.(B|C)C.*") #Original Regex used in the first version of the paper
#regex= lego.parse(".*(a|b|c)(d|e)(a|f|g).*")
regex = regex.reduce()

#Converting to FSM
myfsm=regex.to_fsm()


#Input Alphabet length
alphabet_length = len(myfsm.alphabet)

#Number of states
States_num = len(myfsm.map)

#...The following block is used to fill-in the the empty transition entries with zeros, if any.
# The greenery modules makes the ""false"" transitions empty when not using .* before the string
# as it doesn't produce a specialzed "failure" state
# By the method below, we will assume any "false" transition to return to zero state
print("This is the fsm before filling with zeros")
print(myfsm)
for s in range(States_num):
    for k in myfsm.alphabet:        
        if k not in myfsm.map[s]:
            myfsm.map[s][k]=0
    tempodict = OrderedDict(sorted(myfsm.map[s].items(), key=msort))    
    myfsm.map[s] = dict(tempodict)
print("This is the fsm after filling")
print(myfsm)
#Constructing the states
States=[]
for s in range(States_num):
    States.append("e"+str(s))


#Number of input bits
Input_bits_num = math.ceil(math.log2(alphabet_length))

#Number of States bits
States_bits_num = math.ceil(math.log2(States_num))

#Building the FSM object for minimization
m = logicmin.FSM(States,States_bits_num,Input_bits_num,1)

#looping therough the states
for s in range(len(States)):
    #Getting target states going out of state s for each alphabet
    target_states = list(myfsm.map[s].values())
    
    #Looping through the input alphabet for each state
    for c in range(alphabet_length):
        input_bits=[]
        num_bin = format(c,"0"+str(Input_bits_num)+"b")
        #Encoding the input alphabet into binary representation for binary fsm
        for b in range(Input_bits_num):
            input_bits.append(num_bin[b])

        #We will construct an output variable that toggles to 1 when the state is in an accepted one
        #The output variable will be calclated according to the current state, as usual
        #In the implementation code of the fsm, the output variable should be calculated after
        #reaching the next state, so that the output would resemble "current output" not "previous output"
        #after calculating the ""next"" state.
        if s in myfsm.finals:
            m.add(input_bits,States[s],States[target_states[c]],'1')
            print(input_bits,States[s],States[target_states[c]],'1')
        else:
            m.add(input_bits,States[s],States[target_states[c]],'0')
            print(input_bits,States[s],States[target_states[c]],'0')

#assigning codes for the states, to make binary fsm
codes = dict()
for i in range(len(States)):
    codes[States[i]]=i
m.assignCodes(codes)    

#solving the fsm with D-FFs
sols = m.solveD()

#These are required for printing
# print solution with input and output names. 
# in format <inputs,states,flip-flop,outputs>
xnames=[]
ynames=[]
for x in reversed(range(Input_bits_num)):
    xnames.append("I"+str(x))
for s in reversed(range(States_bits_num)):
    xnames.append("S"+str(s))
    ynames.append("D"+str(s))
ynames.append("Y")

print(sols.printN(xnames, ynames))

#------------Exporting the FSM-------------
#Number of states bits
#Number of input bits
#Number of output bits
#For each output:
#   Number of terms
#   For each term
#       True and False number (t,f)
#For each state bit:
#   Number of terms
#   For each term
#       True and False number (t,f)

O_S = sols.sols                              #List Outputs and Sataes expressions, each item is an SOP
fsmfile = open('fsm.txt','w')
fsmfile.write(str(States_bits_num) + '\n')   #number of states bits (Number of D flip flops)
fsmfile.write(str(Input_bits_num) + '\n')    #number of input bits  (Number of input lines)
fsmfile.write(str(1) + '\n')                 #number of outputs (=1)
#Writing expressions
#The expression is written in terms of True and False and x.
#The ones in the True number (.t) represents the locations of uninverted letters
#The ones in the False number(.f) represents the locations of inverted letters
#If a locationd doesn't contain a true or fales 1, then the letter doesn't exist in the term

#Writing the output expression
for j in range(1):                           
    out = O_S[j]
    fsmfile.write(str(len(out.cubes))+ '\n');           #print number of (product)terms in the expressions
    for k in range(len(out.cubes)):
        fsmfile.write(str(out.cubes[k].t)+ ' ' + str(out.cubes[k].f) + '\n');           #print number of (product)terms in the expressions

#Writing the next states expression
for j in range(1, States_bits_num+1):
    state = O_S[j]
    fsmfile.write(str(len(state.cubes))+ '\n');           #print number of (product)terms in the expressions
    for k in range(len(state.cubes)):
        fsmfile.write(str(state.cubes[k].t)+ ' ' + str(state.cubes[k].f) + '\n');           #print number of (product)terms in the expressions
fsmfile.close()


#----------Exporting the encoding table-----------
PCodeTable = open('PCodeTable.txt','w')
#Number of input bits (Encoded bits)
#256 line of integer encoding values
code_value = 0
code_table = [None]*256

PCodeTable.write(str(Input_bits_num) + '\n')
#Filling the used alphabet locations with encoding values
for k in sorted(myfsm.alphabet,key=msort):
    if k is not fsm.anything_else:
        code_table[ord(k)]=code_value
        code_value += 1

#Filling the rest of the locations with a constant value and wirting the file
for k in range(len(code_table)):
    if code_table[k] is None:
        code_table[k] = code_value
    PCodeTable.write(str(code_table[k])+'\n')
PCodeTable.close()
print("FSM file is written")
