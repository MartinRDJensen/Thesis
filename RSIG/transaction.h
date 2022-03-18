#include "RSIG/CurveElement.h"
#include <vector>


class BlockChainTransaction{
    private:
        int amount;
    public:
        CurveElement destination_key;
        CurveElement key_image;
        BlockChainTransaction(int amount);
        void set_transaction(); 
};

class BlockChain{
    public:
        std::vector<BlockChainTransaction> block_chain;
        BlockChain();
        void add_transaction(BlockChainTransaction);
        void print_block_chain();
};


class SignatureTransaction{
    private:
        int amount;
    public:
        CurveElement TX_pk;
        CurveElement key_image;
        std::vector<CurveElement> destination_key_coll;
        SignatureTransaction(int amount);
        void sample_destination_keys(int n, BlockChain block_chain);
        void set_transaction(CurveElement A, CurveElement B);
        static unsigned char convert(SignatureTransaction TX);
};
