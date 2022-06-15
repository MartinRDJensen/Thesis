#include "CurveElement.h"
#include "util.h"
#include <vector>


class BlockChainTransaction{
  private:
      int amount;
  public:
      int get_amount() { return amount; }
      CurveElement destination_key;
      CurveElement key_image;
      BlockChainTransaction(int amount);
      void make_fake_tx(int n);
};

class BlockChain{
  public:
      std::vector<BlockChainTransaction> block_chain;
      BlockChain();
      void bc_add_transaction(BlockChainTransaction);
      void print_block_chain();
};


class SignatureTransaction{
  private:
      int amount;
  public:
      int get_amount() { return amount; }
      CurveElement TX_pk;
      CurveElement key_image;
      std::vector<CurveElement> destination_key_coll;
      SignatureTransaction(int amount, CurveElement A, CurveElement B, CurveElement key_image);
      void sample_destination_keys(int n, BlockChain block_chain);
};

SignatureTransaction *genTransaction(CurveElement I);
