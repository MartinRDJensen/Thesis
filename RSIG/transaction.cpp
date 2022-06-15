#include "RSIG/transaction.h"
#include <iostream>

BlockChainTransaction::BlockChainTransaction(int amount)
  : amount(amount) {
}


void BlockChainTransaction::make_fake_tx(int n){
  /*
   *   JUST USED TO SPAWN FAKE PREVIOUS TRANSACTIONS
   *   WORKS AS WHEN THEY ARE MADE CORRECTLY THEN THE
   *   DESTINATION KEY IS SEEN AS D = xG, where
   *   x = Hs(aR) + b
   */
  auto keys = gen(n);
  destination_key = get<1>(keys);
  key_image = get<2>(keys);
}

BlockChain::BlockChain(){
  std::cout << "block chain created." << std::endl;
}

void BlockChain::print_block_chain(){
  for(BlockChainTransaction TX : block_chain){
      std::cout << TX.destination_key << std::endl;
  }
  std::cout << "Total amount on block chain is: " << block_chain.size() << std::endl;
}

void BlockChain::bc_add_transaction(BlockChainTransaction TX){
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

SignatureTransaction::SignatureTransaction(int amount, CurveElement A, CurveElement B, CurveElement key_image)
  : amount(amount), key_image(key_image) {
  CurveElement G(1);

  //Computes transaction's public key
  auto r = SeededPRNG().get<CurveElement::Scalar>();
  CurveElement R = G.operator*(r);
  TX_pk = R;

  //Computing D = Hs(rA)G + B
  CurveElement rA = A.operator*(r);
  unsigned char h[crypto_hash_sha512_BYTES];
  CurveElement::get_hash(h, rA);
  CurveElement::Scalar h_rA = hash_to_scalar(h);
  CurveElement hashG = G.operator*(h_rA);
  CurveElement dest_key = hashG.operator+(B);
  destination_key_coll.push_back(dest_key);
}

void SignatureTransaction::sample_destination_keys(int n, BlockChain bc){
  int count = 0;
  for(BlockChainTransaction tx : bc.block_chain) {
    //FIDDLE WITH RANDOM SAMPLING AT SOME POINT
    int rando = (rand() % 10) +1;
    if(count == n){ break; }
    if(rando >= 5){
      destination_key_coll.push_back(tx.destination_key);
      count++;
   }
  }
}

SignatureTransaction *genTransaction(CurveElement I) {
  auto key1 = gen(150);
  auto destination_key1 = get<1>(key1);
  auto key2 = gen(300);
  auto destination_key2 = get<1>(key2);
  //sender / receiver
  BlockChain bc;
  for (int i = 0; i < 10; i++) {
    BlockChainTransaction tx(i);
    tx.make_fake_tx(i+5);
    bc.bc_add_transaction(tx);
  }

  SignatureTransaction *sign_tx = new SignatureTransaction(
      1000, destination_key1, destination_key2, I);
  sign_tx->sample_destination_keys(4, bc);

  return sign_tx;
}
