#include "ECDSA/CurveElement.h"

//#include "ECDSA/P256Element.h"
#include "Math/gfp.hpp"
#include "Tools/Bundle.h"
#include <vector>
#include "util.h"
CurveElement generator(1);


template<template<class U> class T>
class RingSignature {
public:
  CurveElement keyImage;
  vector<T<CurveElement::Scalar>> challenges;
  vector<T<CurveElement::Scalar>> responses;
};




template<template<class U> class T>
RingSignature<T> sign(SignatureTransaction *tx, 
        //size_t length,
        RSIGTuple<T> tuple,
        typename T<CurveElement::Scalar>::MAC_Check& MCp,
        typename T<CurveElement>::MAC_Check& MCc,
        Player& P,
        //RSIGOptions opts,
        T<CurveElement::Scalar> sk,
        CurveElement I,
        SubProcessor<T<CurveElement::Scalar>>& proc
        )
{

  typedef T<typename CurveElement::Scalar> scalarShare;
  //typedef T<CurveElement> pointShare;

    Timer timer;
    timer.start();
    auto stats = P.total_comm();
    RingSignature<T> signature;

    auto& protocol = proc.protocol;

    vector<CurveElement> opened_L;
    vector<CurveElement> opened_R;
    
    MCc.POpen_Begin(opened_L, tuple.secret_L, P);
    MCc.POpen_End(opened_L, tuple.secret_L, P);

  
    MCc.POpen_Begin(opened_R, tuple.secret_R, P); 
    MCc.POpen_End(opened_R, tuple.secret_R, P);  
    
    vector<CurveElement::Scalar> opened_bit;
    
    MCp.POpen_Begin(opened_bit, tuple.eq_bit_shares, P);
    MCp.POpen_End(opened_bit, tuple.eq_bit_shares, P);

    for(auto x : opened_bit) {
      cout << "bit is: " << x << endl;
    }
    
    unsigned char* m = reinterpret_cast<unsigned char *>(tx);
    
    CurveElement::Scalar c = crypto_hash(m, opened_L, opened_R);
    
    for(int i = 0 ; i < 6 ; i++) {
      cout << "L IS " << opened_L.at(i) << " and R is " << opened_R.at(i) << endl;  
    }


    auto shareOfC =  scalarShare::constant(c, P.my_num(), MCp.get_alphai());
    cout << " challenge " << c << endl;
    scalarShare w;
    
    for(auto tmp : tuple.w_values) {
      w = w + tmp;
    }
    
  protocol.init_mul();
  for(int i = 0; i < 6; i++) {
    auto tmp = shareOfC - w + tuple.w_values.at(i); 
    protocol.prepare_mul(tmp, tuple.eq_bit_shares.at(i));

  }

  protocol.start_exchange();
  protocol.stop_exchange();
  vector<scalarShare> challenges;
  for(int i = 0; i < 6; i++) {
    auto tmp = protocol.finalize_mul() + tuple.w_mul_const_sub_bit.at(i);
    challenges.push_back(tmp);
  }


  vector<scalarShare> responses;
  protocol.init_mul();
  for(int i = 0; i < 6; i++) {
    protocol.prepare_mul(sk, tuple.eq_bit_shares.at(i));
  }

  protocol.start_exchange();
  protocol.stop_exchange();
  for(int i = 0; i < 6; i++) {
    auto tmp = protocol.finalize_mul();
    responses.push_back(tmp);
  }

  protocol.init_mul();
  for(int i = 0; i < 6; i++) {
    protocol.prepare_mul(responses.at(i), challenges.at(i));
  }

  protocol.start_exchange();
  protocol.stop_exchange();
  for(int i = 0; i < 6; i++) {
    auto tmp = protocol.finalize_mul();
    responses.at(i) = tuple.q_values.at(i) -  tmp;
  }

  signature.challenges = challenges;
  signature.responses = responses;
  signature.keyImage = I;
  return signature;
}
    
template<template<class U> class T>   
bool check(RingSignature<T> signature, SignatureTransaction *tx, std::vector<CurveElement> publicKeys, Player& P, typename T<CurveElement::Scalar>::MAC_Check& MCp)
{
    Timer timer;
    timer.start();
    //signature.s.check();
    //signature.R.check();

    vector<CurveElement::Scalar> opened_c;
    vector<CurveElement::Scalar> opened_r;

    MCp.POpen_Begin(opened_c, signature.challenges, P);
    MCp.POpen_End(opened_c, signature.challenges, P);

  
    MCp.POpen_Begin(opened_r, signature.responses, P); 
    MCp.POpen_End(opened_r, signature.responses, P);  
    

  std::vector<CurveElement> R;
  std::vector<CurveElement> L;

  for (vector<int>::size_type i = 0; i < publicKeys.size(); i++) {
    CurveElement rG = generator.operator*(opened_r.at(i));
    CurveElement cP = publicKeys.at(i).operator*(opened_c.at(i));
    L.push_back(rG.operator+(cP));

    unsigned char h[crypto_hash_sha512_BYTES];
    CurveElement::get_hash(h, publicKeys.at(i));
    CurveElement hP = CurveElement::hash_to_group(h);
    CurveElement rH = hP.operator*(opened_r.at(i));
    CurveElement cI = signature.keyImage.operator*(opened_c.at(i));
    R.push_back(rH.operator+(cI));
  }

  unsigned char *m = reinterpret_cast<unsigned char *>(tx);
  CurveElement::Scalar challenge_prime = crypto_hash(m, L, R);

  for(int i = 0 ; i < 6 ; i++) {
      cout << "L IS " << L.at(i) << " and R is " << R.at(i) << endl;  
    }


  CurveElement::Scalar rebuildChallenge;
  for (vector<int>::size_type i = 0; i < publicKeys.size(); i++) {
    rebuildChallenge = rebuildChallenge + opened_c.at(i);
  }
  cout << "Final verification check becomes" << endl;
  cout << challenge_prime << "=?=" << rebuildChallenge << endl;
  assert(challenge_prime.operator==(rebuildChallenge));
  std::cout << "Offline checking took: " << timer.elapsed() * 1e3 << " ms. "
            << std::endl;
  return true;
}


template<template<class U> class T>
void sign_benchmark(SignatureTransaction* message,
        vector<RSIGTuple<T>>& tuples, 
         T<CurveElement::Scalar> sk,
        CurveElement I,
        std::vector<CurveElement> publicKeys, 
        typename T<CurveElement::Scalar>::MAC_Check& MCp, Player& P,
        SubProcessor<T<CurveElement::Scalar>>& proc
        )
{
   
    typename T<CurveElement>::Direct_MC MCc(MCp.get_alphai());

    // synchronize
    Bundle<octetStream> bundle(P);
    P.unchecked_broadcast(bundle);
    Timer timer;
    timer.start();
    auto stats = P.total_comm();
 
    for (size_t i = 0; i < min(10lu, tuples.size()); i++)
    { 
        
        check(sign(message, tuples[i], MCp, MCc, P, sk, I, proc), message, publicKeys, P, MCp);
        /*
        if (not opts.check_open)
            continue;
        Timer timer;
        timer.start();
        auto& check_player = MCp.get_check_player(P);
        auto stats = check_player.total_comm();
        MCp.Check(P);
        MCc.Check(P);
        auto diff = (check_player.total_comm() - stats);
        cout << "Online checking took " << timer.elapsed() * 1e3 << " ms and sending "
            << diff.sent << " bytes" << endl;
        diff.print();
    }
    */
  }
}

