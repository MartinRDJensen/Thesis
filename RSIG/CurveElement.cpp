/*
 * Element.cpp
 *
 */

#include <ECDSA/CurveElement.h>

#include "Math/gfp.hpp"

unsigned char CurveElement::zero[crypto_core_ristretto255_BYTES];

void CurveElement::init()
{
    Scalar::init_field(
            (bigint(1) << 252) + bigint("27742317777372353535851937790883648493"),
            false);
    if(sodium_init() == -1)
        throw runtime_error("cannot initalize sodium");
    unsigned char tmp[crypto_core_ristretto255_SCALARBYTES];
    memset(tmp, 0, sizeof(tmp));
    crypto_scalarmult_ristretto255_base(zero, tmp);
}

void CurveElement::convert(unsigned char* res, const Scalar& other)
{
    bigint tmp;
    tmp = other;

    memset(res, 0, crypto_core_ristretto255_SCALARBYTES);
    memcpy(res, tmp.__get_mp()->_mp_d, abs(tmp.__get_mp()->_mp_size) * sizeof(mp_limb_t));
}

CurveElement::CurveElement()
{
    memcpy(a, zero, sizeof(a));
    check();
}

CurveElement::CurveElement(const Scalar& other)
{
    unsigned char tmp[crypto_core_ristretto255_SCALARBYTES];
    convert(tmp, other);
    crypto_scalarmult_ristretto255_base(a, tmp);
    check();
}

CurveElement CurveElement::mult_by_base(){
    CurveElement res;
    crypto_scalarmult_ristretto255_base(res.a, a);
    res.check();
    return res;
}
CurveElement CurveElement::hash_to_elem(unsigned char *r) {
    CurveElement res;
    crypto_core_ristretto255_from_hash(res.a, r);
    res.check();
    return res;
}
CurveElement CurveElement::multi(const CurveElement& scalar){
    CurveElement res;
    int tmp = crypto_scalarmult_ristretto255(res.a, a, scalar.a);
    std::cout << "res from mult: " << tmp << std::endl;
    res.check();
    return res;
}

CurveElement::CurveElement(word other)
{
    if (other == 0)
    {
        *this = CurveElement();
        return;
    }
    unsigned char tmp[crypto_core_ristretto255_SCALARBYTES];
    memset(tmp, 0, sizeof(tmp));
    memcpy(tmp, &other, sizeof(other));
    crypto_scalarmult_ristretto255_base(a, tmp);
    check();
}

void CurveElement::set_a(const unsigned char new_a){
   // std::strcpy(a, new_a);
    std::cout << new_a;
}

void CurveElement::make_random_element(){
    crypto_core_ristretto255_scalar_random(a);
    check();
}

void CurveElement::check()
{
#ifdef CURVE_CHECK
    if (crypto_core_ristretto255_is_valid_point(a) != 1)
        throw runtime_error("curve point not valid");
#endif
}

CurveElement CurveElement::operator +(const CurveElement& other) const
{
    CurveElement res;
    crypto_core_ristretto255_add(res.a, a, other.a);
    res.check();
    return res;
}

CurveElement CurveElement::operator -(const CurveElement& other) const
{
    CurveElement res;
    crypto_core_ristretto255_sub(res.a, a, other.a);
    res.check();
    return res;
}

CurveElement CurveElement::operator *(const Scalar& other) const
{
    CurveElement res;
    unsigned char tmp[crypto_core_ristretto255_SCALARBYTES];
    convert(tmp, other);
    if (crypto_scalarmult_ristretto255(res.a, tmp, a) < 0)
    {
        cerr << "EC multiplication by zero" << endl;
    }
    res.check();
    return res;
}

CurveElement& CurveElement::operator +=(const CurveElement& other)
{
    *this = *this + other;
    return *this;
}

bool CurveElement::operator ==(const CurveElement& other) const
{
    for (size_t i = 0; i < sizeof a; i++)
        if (a[i] != other.a[i])
            return false;
    return true;
}

bool CurveElement::operator !=(const CurveElement& other) const
{
    return not (*this == other);
}

void CurveElement::pack(octetStream& os) const
{
    os.append(a, sizeof(a));
}

void CurveElement::unpack(octetStream& os)
{
    os.consume(a, sizeof(a));
    check();
}

ostream& operator <<(ostream& s, const CurveElement& x)
{
    s << hex << *(word*)x.get();
    return s;
}

octetStream CurveElement::hash(size_t n_bytes) const
{
    octetStream os;
    pack(os);
    auto res = os.hash();
    assert(n_bytes >= res.get_length());
    res.resize_precise(n_bytes);
    return res;
}
