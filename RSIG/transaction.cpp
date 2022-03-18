#include "RSIG/transaction.h"
#include "ECDSA/CurveElement.h"

BlockChainTransaction::BlockChainTransaction(int amount){
    amount = amount;
}


void BlockChainTransaction::set_transaction(CurveElement A, CurveElement B){
//dest, keyimg
    CurveElement::Scalar r =  
}



SignatureTransaction::SignatureTransaction(){

}


unsigned char SignatureTransaction::convert(SignatureTransaction){

}
