#include "RSIG/party.h"
#include <iostream>
Party::Party(){
    auto keys = gen();
    secret_key_a = get<0>(keys);
    public_key_A = get<1>(keys);
    keys = gen();
    secret_key_b = get<0>(keys);
    public_key_B = get<1>(keys);
}


bool Party::is_transaction_for_me(SignatureTransaction tx) {
    CurveElement G(1);
    CurveElement aR = tx.TX_pk.operator*(secret_key_a);
    unsigned char h[crypto_hash_sha512_BYTES];
    CurveElement::get_hash(h, aR);
    CurveElement::Scalar h_aR = hash_to_scalar(h);
    CurveElement h_aR_G = G.operator*(h_aR);
    CurveElement D_prime = h_aR_G.operator+(public_key_B);

    bool is_receiver = false;

    for(CurveElement key : tx.destination_key_coll) {
        if (D_prime.operator==(key)) {
            is_receiver = true;
        }

    }
    return is_receiver;
}
void Party::include_new_transaction(CurveElement::Scalar x){
    wallet.push_back(x);
}
