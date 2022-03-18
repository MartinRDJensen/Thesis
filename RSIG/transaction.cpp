#include "RSIG/transaction.h"
#include "ECDSA/CurveElement.h"
#include <iostream>

BlockChainTransaction::BlockChainTransaction(int amount)
    : amount(amount) {
}


void BlockChainTransaction::set_transaction(){
    /*
     *   JUST USED TO SPAWN FAKE PREVIOUS TRANSACTIONS
     *   WORKS AS WHEN THEY ARE MADE CORRECTLY THEN THE
     *   DESTINATION KEY IS SEEN AS D = xG, where
     *   x = Hs(aR) + b
     */
    auto keys = gen();
    destination_key = get<1>(keys);
    key_image = get<2>(keys);
}

BlockChain::BlockChain(){
    std::cout << "block_chain created yay" << std::endl;
}

void BlockChain::print_block_chain(){
    for(BlockChainTransaction TX : block_chain){
        std::cout << TX << std::endl;
    }
    std::cout << "Total amount on block chain is: " << block_chain.size() << std::endl;
}

void BlockChain::add_transaction(BlockChainTransaction TX){
    bool valid_transaction = true;
    for(BlockChainTransaction existing_TX : block_chain) {
        if(existing_TX.key_image == TX.key_image){
            valid_transaction = false;
        }
    }

    if(valid_transaction){
        block_chain.push_back(TX);
    }
}
CurveElement TX_pk;
        CurveElement key_image;
        std::vector<CurveElement> destination_key_coll;
        SignatureTransaction(int amount);
        void sample_destination_keys(int n, BlockChain block_chain);
        void set_transaction(CurveElement A, CurveElement B);
        static unsigned char convert(SignatureTransaction TX);

SignatureTransaction::SignatureTransaction(int amount, Party receiver, CurveElement key_image)
    : amount(amount), key_image(key_image) {
    CurveElement G(1);

    //Computes transaction's public key
    auto r = SeededPRNG().get<CurveElement::Scalar>();
    CurveElement R = G.operator*(r);
    TX_pk = R;
    
    //Computing D = Hs(rA)G + B
    CurveElement rA = receiver.public_key_A.operator*(r);
    CurveElement h = CurveElement::get_hash(rA);
    CurveElement::Scalar h_rA = hash_to_scalar(h);
    CurveElement hashG = G.operator*(h_rA);
    CurveElement dest_key = hashG.operator+(B);
    destination_key_coll.push_back(dest_key);
}

SignatureTransaction::sample_destination_keys(int n, BlockChain block_chain){
    for(BlockChain tx : block_chain) {
       int rand = (rand() % 10) +1;
       if(destination_key_coll.size() == n){ break; }
       if(rand >= 5){
            destination_key_coll.push_back(tx);
       }
    }
}

unsigned char SignatureTransaction::convert(SignatureTransaction){

}
