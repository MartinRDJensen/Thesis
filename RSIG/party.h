#include "ECDSA/CurveElement.h"
#include "RSIG/ring_signature.h"

class Party{ 
    private:
        CurveElement::Scalar secret_key_a;
        CurveElement::Scalar secret_key_b;
        int num;
        //thing of transactions
    public:
        CurveElement public_key_A;
        CurveElement public_key_B;
        Party();
};


