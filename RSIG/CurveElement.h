/*
 * Element.h
 *
 */

#ifndef ECDSA_CURVEELEMENT_H_
#define ECDSA_CURVEELEMENT_H_

#include <sodium.h>

#include "Math/gfp.h"

class CurveElement : public ValueInterface
{
public:
    typedef gfp_<2, 4> Scalar;

private:
    static unsigned char zero[crypto_core_ristretto255_BYTES];

    unsigned char a[crypto_core_ristretto255_BYTES];

    static void convert(unsigned char* res, const Scalar& other);

public:
    typedef void next;
    typedef void Square;

    static int size() { return sizeof(a); }
    static string type_string() { return "Curve25519"; }

    static void init();

    CurveElement();
    CurveElement(const Scalar& other);
    CurveElement(word other);

    void check();

    const unsigned char* get() const { return a; }

    CurveElement operator+(const CurveElement& other) const;
    CurveElement operator-(const CurveElement& other) const;
    CurveElement operator*(const Scalar& other) const;
    static void get_hash(unsigned char* out, CurveElement to_hash);
    static CurveElement new_mult(const CurveElement& x, const CurveElement& y);
    static CurveElement new_add(const CurveElement& x, const CurveElement& y);
    static CurveElement new_sub(const CurveElement& x, const CurveElement& y);
    static CurveElement random_group_element();
    static CurveElement random_scalar_element();
    static CurveElement hash_to_group(unsigned char* h);
    static CurveElement base_mult(CurveElement& other);

    static CurveElement::Scalar modulos(const Scalar& a, const Scalar& b);

    CurveElement reduce();

    CurveElement& operator+=(const CurveElement& other);

    bool operator==(const CurveElement& other) const;
    bool operator!=(const CurveElement& other) const;

    void assign_zero() { *this = 0; }
    bool is_zero() { return *this == 0; }
    void add(octetStream& os) { *this += os.get<CurveElement>(); }

    void pack(octetStream& os) const;
    void unpack(octetStream& os);

    octetStream hash(size_t n_bytes) const;
};

CurveElement operator*(const CurveElement::Scalar& x, const CurveElement& y);
ostream& operator<<(ostream& s, const CurveElement& x);

#endif /* ECDSA_CURVEELEMENT_H_ */
