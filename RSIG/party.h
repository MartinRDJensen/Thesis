#include "CurveElement.h"
#include "RSIG/transaction.h"
#include <vector>


class Party{
    private:
        CurveElement::Scalar secret_key_a;
        CurveElement::Scalar secret_key_b;
        //std::vector<BlockChainTransaction> wallet;
        std::vector<CurveElement::Scalar> wallet;
    public:
        CurveElement public_key_A;
        CurveElement public_key_B;
        Party();
        bool is_transaction_for_me(SignatureTransaction TX);

        //update below to add block_chain transactino at some point
        void include_new_transaction(CurveElement::Scalar x);
};


