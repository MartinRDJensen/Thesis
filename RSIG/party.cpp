#include "RSIG/party.h"
Party::Party(){
    auto keys = gen();
    secret_key_a = get<0>(keys);
    public_key_A = get<1>(keys);
    keys = gen();
    secret_key_b = get<0>(keys);
    public_key_B = get<1>(keys);
}

