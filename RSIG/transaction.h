#include "RSIG/CurveElement.h"
#include <vector>


class BlockChainTransaction{
    private:
        int amount;
    public:
        CurveElement destination_key;
        CurveElement key_image;
        BlockChainTransaction(int amount);
        void set_transaction(CurveElement A, CurveElement B); 
};

class SignatureTransaction{
    private:
        int amount;
    public:
        CurveElement TX_pk;
        CurveElement key_image;
        std::vector<CurveElement> destination_key_coll;
        SignatureTransaction(int amount);
        static unsigned char convert(SignatureTransaction TX);
};
