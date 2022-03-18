#include "RSIG/party.h"
#include "RSIG/ring_signature.h"

int main(){
    Party sender;
    Party receiver;
    BlockChain bc;
    for(int i = 0; i < 1000; i++){
        BlockChainTransaction tx(i);
        tx.make_fake_tx();
        bc.bc_add_transaction(tx);
    }
    bc.print_block_chain();
    
    auto test_keys = gen();
    
    SignatureTransaction sign_tx(1000, receiver.public_key_A, receiver.public_key_B, get<2>(test_keys));
    sign_tx.sample_destination_keys(100, bc);
}
