#include "RSIG/party.h"
using namespace std;

int main(){
    Party sender;
    Party receiver;
    BlockChain bc;

    
    for(int i = 0; i < 10; i++){
        BlockChainTransaction tx(i);
        tx.make_fake_tx();
        bc.bc_add_transaction(tx);
    }
    bc.print_block_chain();
    
    auto test_keys = gen();
    
    SignatureTransaction* sign_tx = new SignatureTransaction(1000, receiver.public_key_A, receiver.public_key_B, get<2>(test_keys));
    sign_tx -> sample_destination_keys(4, bc);
    

    // Burde bruge dest og one time private key i stedet for
    vector<CurveElement> tmp;
    tmp.push_back(get<1>(test_keys));
    for (int i = 0; i < 5; i++) {
        auto tmp_keys = gen();
        tmp.push_back(get<1>(tmp_keys));
    }

    unsigned char* m = reinterpret_cast<unsigned char*>(sign_tx);

    sign_values v = j(m, get<0>(test_keys), tmp, sign_tx -> key_image);
    split_c(&v);
    set_r_values(get<0>(test_keys), &v);
    cout << "oihjio" << endl;
    bool verifies = verify(&v);
    assert(verifies);
    cout << "yay it verififes" << endl;


    cout << receiver.is_transaction_for_me(*sign_tx) << endl;

}
