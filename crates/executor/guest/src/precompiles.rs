//! Precompile arithmetic over the zkVM's curve and field syscalls.
//!
//! revm's default `Crypto` backends run bn254 scalar multiplication in
//! Jacobian coordinates and every BLS12-381 operation on arkworks' pure
//! Montgomery arithmetic, both of which are ordinary MIPS code in the guest.
//! These routines take the same byte inputs and compute with the `bn`
//! fork's affine syscalls and the `bls12_381` fork's syscall-backed field.

use bls12_381::{
    fp::Fp, fp2::Fp2, hash_to_curve::MapToCurve, multi_miller_loop, G1Affine, G1Projective,
    G2Affine, G2Prepared, G2Projective, Gt, Scalar,
};
use kzg_rs::{
    kzg_proof::{safe_g1_affine_from_bytes, safe_scalar_affine_from_bytes},
    Bytes32, Bytes48, KzgSettings,
};
use revm::precompile::PrecompileError;

const FP: usize = 48;

// ---------------------------------------------------------------------------
// bn254

/// The `ecAdd` precompile on two 64-byte points.
pub fn bn254_g1_add(p1: &[u8], p2: &[u8]) -> Result<[u8; 64], PrecompileError> {
    let a = bn254::point(p1)?;
    let b = bn254::point(p2)?;
    Ok(bn254::encode(bn254::add(a, b)))
}

/// The `ecMul` precompile on a 64-byte point and a 32-byte big-endian scalar.
pub fn bn254_g1_mul(point: &[u8], scalar: &[u8]) -> Result<[u8; 64], PrecompileError> {
    let p = bn254::point(point)?;
    Ok(bn254::encode(bn254::mul(p, scalar)))
}

/// bn254 G1 in affine coordinates over the zkVM's curve precompiles, which
/// add two distinct finite points and double a finite point; infinity and
/// the equal-`x` cases are decided here.  A point is `x || y` as 32-bit
/// little-endian words, the layout the precompiles read.
#[cfg(target_os = "zkvm")]
mod bn254 {
    use revm::precompile::PrecompileError;
    use zkm_lib::{syscall_bn254_add, syscall_bn254_double, syscall_uint256_mulmod};

    type Words = [u32; 8];
    pub type Point = [u32; 16];

    /// The base field modulus `p`, little-endian words.
    const P: Words = [
        0xd87cfd47, 0x3c208c16, 0x6871ca8d, 0x97816a91, 0x8181585d, 0xb85045b6, 0xe131a029,
        0x30644e72,
    ];
    /// The group order `n`, little-endian words.
    const N: Words = [
        0xf0000001, 0x43e1f593, 0x79b97091, 0x2833e848, 0x8181585d, 0xb85045b6, 0xe131a029,
        0x30644e72,
    ];
    const ONE: Words = [1, 0, 0, 0, 0, 0, 0, 0];
    const THREE: Words = [3, 0, 0, 0, 0, 0, 0, 0];

    fn words(be: &[u8]) -> Words {
        let mut w = [0u32; 8];
        for (i, word) in w.iter_mut().enumerate() {
            *word = u32::from_be_bytes(be[28 - 4 * i..32 - 4 * i].try_into().expect("4 bytes"));
        }
        w
    }

    fn bytes(w: &Words, be: &mut [u8]) {
        for (i, word) in w.iter().enumerate() {
            be[28 - 4 * i..32 - 4 * i].copy_from_slice(&word.to_be_bytes());
        }
    }

    fn lt(a: &Words, b: &Words) -> bool {
        for i in (0..8).rev() {
            if a[i] != b[i] {
                return a[i] < b[i];
            }
        }
        false
    }

    /// `(a · b) mod m` through the 256-bit multiplier, which reads `b` and
    /// `m` as one 16-word block.
    fn mul_mod(a: &Words, b: &Words, m: &Words) -> Words {
        let mut x = *a;
        let mut bm = [0u32; 16];
        bm[..8].copy_from_slice(b);
        bm[8..].copy_from_slice(m);
        unsafe { syscall_uint256_mulmod(&mut x, bm.as_ptr().cast()) };
        x
    }

    /// `(a + b) mod p` for `a, b < p`.
    fn add_mod_p(a: &Words, b: &Words) -> Words {
        let mut r = [0u32; 8];
        let mut carry = 0u64;
        for i in 0..8 {
            let s = a[i] as u64 + b[i] as u64 + carry;
            r[i] = s as u32;
            carry = s >> 32;
        }
        if carry != 0 || !lt(&r, &P) {
            let mut borrow = 0i64;
            for i in 0..8 {
                let d = r[i] as i64 - P[i] as i64 - borrow;
                r[i] = d as u32;
                borrow = (d < 0) as i64;
            }
        }
        r
    }

    /// A point from its 64-byte big-endian `x || y` encoding, `None` for
    /// `(0, 0)`; the coordinates must be canonical and on `y² = x³ + 3`.
    pub fn point(be: &[u8]) -> Result<Option<Point>, PrecompileError> {
        let x = words(&be[..32]);
        let y = words(&be[32..64]);
        if !lt(&x, &P) || !lt(&y, &P) {
            return Err(PrecompileError::Bn254FieldPointNotAMember);
        }
        if x == [0; 8] && y == [0; 8] {
            return Ok(None);
        }
        let lhs = mul_mod(&y, &y, &P);
        let rhs = add_mod_p(&mul_mod(&mul_mod(&x, &x, &P), &x, &P), &THREE);
        if lhs != rhs {
            return Err(PrecompileError::Bn254AffineGFailedToCreate);
        }
        let mut p = [0u32; 16];
        p[..8].copy_from_slice(&x);
        p[8..].copy_from_slice(&y);
        Ok(Some(p))
    }

    pub fn encode(p: Option<Point>) -> [u8; 64] {
        let mut out = [0u8; 64];
        if let Some(p) = p {
            bytes(p[..8].try_into().expect("8 words"), &mut out[..32]);
            bytes(p[8..].try_into().expect("8 words"), &mut out[32..]);
        }
        out
    }

    fn double(mut p: Point) -> Point {
        unsafe { syscall_bn254_double(&mut p) };
        p
    }

    /// `a + b`: equal points are doubled, opposite points (equal `x`) cancel.
    pub fn add(a: Option<Point>, b: Option<Point>) -> Option<Point> {
        match (a, b) {
            (None, b) => b,
            (a, None) => a,
            (Some(mut a), Some(b)) => {
                if a[..8] == b[..8] {
                    if a[8..] == b[8..] {
                        Some(double(a))
                    } else {
                        None
                    }
                } else {
                    unsafe { syscall_bn254_add(&mut a, &b) };
                    Some(a)
                }
            }
        }
    }

    /// `k · p` by double-and-add.  `k` is reduced modulo `n` first, so no
    /// partial sum `k' · p` with `k' ≤ k / 2 < n - 1` equals `-p`, the one
    /// case the addition cannot take; the partial sum `p` itself is only
    /// ever doubled.
    pub fn mul(p: Option<Point>, k: &[u8]) -> Option<Point> {
        let p = p?;
        let k = mul_mod(&words(k), &ONE, &N);
        let mut acc: Option<Point> = None;
        for i in (0..8).rev() {
            for j in (0..32).rev() {
                if let Some(a) = acc {
                    acc = Some(double(a));
                }
                if (k[i] >> j) & 1 == 1 {
                    acc = add(acc, Some(p));
                }
            }
        }
        acc
    }
}

/// bn254 G1 off the zkVM, through the `bn` crate.
#[cfg(not(target_os = "zkvm"))]
mod bn254 {
    use bn::{AffineG1, Fq, Fr, G1};
    use revm::precompile::PrecompileError;

    pub type Point = G1;

    pub fn point(be: &[u8]) -> Result<Option<Point>, PrecompileError> {
        let x =
            Fq::from_slice(&be[..32]).map_err(|_| PrecompileError::Bn254FieldPointNotAMember)?;
        let y =
            Fq::from_slice(&be[32..64]).map_err(|_| PrecompileError::Bn254FieldPointNotAMember)?;
        if x.is_zero() && y.is_zero() {
            return Ok(None);
        }
        AffineG1::new(x, y)
            .map(|p| Some(p.into()))
            .map_err(|_| PrecompileError::Bn254AffineGFailedToCreate)
    }

    pub fn encode(p: Option<Point>) -> [u8; 64] {
        let mut out = [0u8; 64];
        if let Some(p) = p.and_then(AffineG1::from_jacobian) {
            p.x().to_big_endian(&mut out[..32]).expect("32 bytes");
            p.y().to_big_endian(&mut out[32..]).expect("32 bytes");
        }
        out
    }

    pub fn add(a: Option<Point>, b: Option<Point>) -> Option<Point> {
        match (a, b) {
            (None, b) => b,
            (a, None) => a,
            (Some(a), Some(b)) => Some(a + b),
        }
    }

    pub fn mul(p: Option<Point>, k: &[u8]) -> Option<Point> {
        let k = Fr::from_slice(k).expect("32 bytes");
        p.map(|p| p * k)
    }
}

// ---------------------------------------------------------------------------
// BLS12-381

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

fn fp(bytes: &[u8; FP]) -> Result<Fp, PrecompileError> {
    Option::from(Fp::from_bytes(bytes)).ok_or(PrecompileError::NonCanonicalFp)
}

fn fp2(c0: &[u8; FP], c1: &[u8; FP]) -> Result<Fp2, PrecompileError> {
    Ok(Fp2 { c0: fp(c0)?, c1: fp(c1)? })
}

/// A G1 point from its EIP-2537 coordinates, `(0, 0)` being the identity;
/// checked to be canonical and on the curve, and in the subgroup when asked.
fn g1(x: &[u8; FP], y: &[u8; FP], subgroup: bool) -> Result<G1Affine, PrecompileError> {
    if is_zero(x) && is_zero(y) {
        return Ok(G1Affine::identity());
    }
    let mut bytes = [0u8; 2 * FP];
    bytes[..FP].copy_from_slice(x);
    bytes[FP..].copy_from_slice(y);
    let p: G1Affine = Option::from(G1Affine::from_uncompressed_unchecked(&bytes))
        .ok_or(PrecompileError::NonCanonicalFp)?;
    if !bool::from(p.is_on_curve()) {
        return Err(PrecompileError::Bls12381G1NotOnCurve);
    }
    if subgroup && !bool::from(p.is_torsion_free()) {
        return Err(PrecompileError::Bls12381G1NotInSubgroup);
    }
    Ok(p)
}

/// A G2 point from its EIP-2537 coordinates `(x0, x1, y0, y1)`.  The
/// library's uncompressed form orders each Fp2 as `c1 || c0`.
fn g2(
    x0: &[u8; FP],
    x1: &[u8; FP],
    y0: &[u8; FP],
    y1: &[u8; FP],
    subgroup: bool,
) -> Result<G2Affine, PrecompileError> {
    if is_zero(x0) && is_zero(x1) && is_zero(y0) && is_zero(y1) {
        return Ok(G2Affine::identity());
    }
    let mut bytes = [0u8; 4 * FP];
    bytes[..FP].copy_from_slice(x1);
    bytes[FP..2 * FP].copy_from_slice(x0);
    bytes[2 * FP..3 * FP].copy_from_slice(y1);
    bytes[3 * FP..].copy_from_slice(y0);
    let p: G2Affine = Option::from(G2Affine::from_uncompressed_unchecked(&bytes))
        .ok_or(PrecompileError::NonCanonicalFp)?;
    if !bool::from(p.is_on_curve()) {
        return Err(PrecompileError::Bls12381G2NotOnCurve);
    }
    if subgroup && !bool::from(p.is_torsion_free()) {
        return Err(PrecompileError::Bls12381G2NotInSubgroup);
    }
    Ok(p)
}

/// The EIP-2537 encoding of a G1 point, zeros for the identity.
fn encode_g1(p: &G1Affine) -> [u8; 2 * FP] {
    if bool::from(p.is_identity()) {
        return [0u8; 2 * FP];
    }
    p.to_uncompressed()
}

/// The EIP-2537 encoding `x0 || x1 || y0 || y1` of a G2 point.
fn encode_g2(p: &G2Affine) -> [u8; 4 * FP] {
    let mut out = [0u8; 4 * FP];
    if bool::from(p.is_identity()) {
        return out;
    }
    let lib = p.to_uncompressed();
    out[..FP].copy_from_slice(&lib[FP..2 * FP]);
    out[FP..2 * FP].copy_from_slice(&lib[..FP]);
    out[2 * FP..3 * FP].copy_from_slice(&lib[3 * FP..]);
    out[3 * FP..].copy_from_slice(&lib[2 * FP..3 * FP]);
    out
}

/// A scalar from 32 big-endian bytes, reduced modulo the group order as
/// EIP-2537 asks.
fn scalar(bytes: &[u8; 32]) -> Scalar {
    let mut wide = [0u8; 64];
    for (i, &b) in bytes.iter().enumerate() {
        wide[31 - i] = b;
    }
    Scalar::from_bytes_wide(&wide)
}

pub type G1Point = ([u8; FP], [u8; FP]);
pub type G2Point = ([u8; FP], [u8; FP], [u8; FP], [u8; FP]);

pub fn bls12_381_g1_add(a: G1Point, b: G1Point) -> Result<[u8; 2 * FP], PrecompileError> {
    let a = g1(&a.0, &a.1, false)?;
    let b = g1(&b.0, &b.1, false)?;
    Ok(encode_g1(&G1Affine::from(G1Projective::from(a) + b)))
}

pub fn bls12_381_g2_add(a: G2Point, b: G2Point) -> Result<[u8; 4 * FP], PrecompileError> {
    let a = g2(&a.0, &a.1, &a.2, &a.3, false)?;
    let b = g2(&b.0, &b.1, &b.2, &b.3, false)?;
    Ok(encode_g2(&G2Affine::from(G2Projective::from(a) + b)))
}

pub fn bls12_381_g1_msm(
    pairs: &mut dyn Iterator<Item = Result<(G1Point, [u8; 32]), PrecompileError>>,
) -> Result<[u8; 2 * FP], PrecompileError> {
    let mut acc = G1Projective::identity();
    for pair in pairs {
        let ((x, y), k) = pair?;
        let p = g1(&x, &y, true)?;
        if bool::from(p.is_identity()) || is_zero(&k) {
            continue;
        }
        acc += p * scalar(&k);
    }
    Ok(encode_g1(&G1Affine::from(acc)))
}

pub fn bls12_381_g2_msm(
    pairs: &mut dyn Iterator<Item = Result<(G2Point, [u8; 32]), PrecompileError>>,
) -> Result<[u8; 4 * FP], PrecompileError> {
    let mut acc = G2Projective::identity();
    for pair in pairs {
        let ((x0, x1, y0, y1), k) = pair?;
        let p = g2(&x0, &x1, &y0, &y1, true)?;
        if bool::from(p.is_identity()) || is_zero(&k) {
            continue;
        }
        acc += p * scalar(&k);
    }
    Ok(encode_g2(&G2Affine::from(acc)))
}

/// Whether the product of the pairings is the identity.  Every point is
/// validated (subgroup included); a pair with an identity contributes the
/// identity and is left out of the Miller loop.
pub fn bls12_381_pairing_check(pairs: &[(G1Point, G2Point)]) -> Result<bool, PrecompileError> {
    let mut g1s = Vec::with_capacity(pairs.len());
    let mut g2s = Vec::with_capacity(pairs.len());
    for ((x, y), (x0, x1, y0, y1)) in pairs {
        let p = g1(x, y, true)?;
        let q = g2(x0, x1, y0, y1, true)?;
        if bool::from(p.is_identity()) || bool::from(q.is_identity()) {
            continue;
        }
        g1s.push(p);
        g2s.push(G2Prepared::from(q));
    }
    if g1s.is_empty() {
        return Ok(true);
    }
    let terms: Vec<(&G1Affine, &G2Prepared)> = g1s.iter().zip(&g2s).collect();
    Ok(multi_miller_loop(&terms).final_exponentiation() == Gt::identity())
}

pub fn bls12_381_fp_to_g1(bytes: &[u8; FP]) -> Result<[u8; 2 * FP], PrecompileError> {
    let u = fp(bytes)?;
    let p = G1Projective::map_to_curve(&u).clear_h();
    Ok(encode_g1(&G1Affine::from(p)))
}

pub fn bls12_381_fp2_to_g2(c: ([u8; FP], [u8; FP])) -> Result<[u8; 4 * FP], PrecompileError> {
    let u = fp2(&c.0, &c.1)?;
    let p = G2Projective::map_to_curve(&u).clear_h();
    Ok(encode_g2(&G2Affine::from(p)))
}

// ---------------------------------------------------------------------------
// KZG point evaluation

/// The pairing check of the KZG point-evaluation precompile with its two
/// G2 arguments fixed, so both are prepared once:
///
/// `e(P - y·G1, G2) · e(-π, τ·G2 - z·G2) = 1`  is, by bilinearity,
/// `e(P - y·G1 + z·π, G2) · e(-π, τ·G2) = 1`,
///
/// which moves the only scalar multiplication to G1, where it is one joint
/// double-and-add over `y` and `z`, and leaves the G2 side constant.
pub struct KzgVerifier {
    g2: G2Prepared,
    tau_g2: G2Prepared,
}

impl KzgVerifier {
    pub fn new(settings: &KzgSettings) -> Self {
        Self {
            g2: G2Prepared::from(G2Affine::generator()),
            tau_g2: G2Prepared::from(settings.g2_points[1]),
        }
    }

    /// Whether `proof` opens `commitment` at `z` to `y`; the points are
    /// decoded with kzg-rs's checks (canonical, on the curve, in the
    /// subgroup), the scalars must be canonical.
    pub fn verify(
        &self,
        z: &[u8; 32],
        y: &[u8; 32],
        commitment: &[u8; 48],
        proof: &[u8; 48],
    ) -> Result<bool, PrecompileError> {
        let other = |err: kzg_rs::KzgError| PrecompileError::other(err.to_string());
        let z = safe_scalar_affine_from_bytes(&Bytes32(*z)).map_err(other)?;
        let y = safe_scalar_affine_from_bytes(&Bytes32(*y)).map_err(other)?;
        let commitment = safe_g1_affine_from_bytes(&Bytes48(*commitment)).map_err(other)?;
        let proof = safe_g1_affine_from_bytes(&Bytes48(*proof)).map_err(other)?;

        let minus_g1 = -G1Affine::generator();
        let a =
            G1Affine::from(linear_combination(&minus_g1, &y, &proof, &z).add_mixed(&commitment));
        let minus_proof = -proof;
        let mut terms: Vec<(&G1Affine, &G2Prepared)> = Vec::with_capacity(2);
        if !bool::from(a.is_identity()) {
            terms.push((&a, &self.g2));
        }
        if !bool::from(minus_proof.is_identity()) {
            terms.push((&minus_proof, &self.tau_g2));
        }
        if terms.is_empty() {
            return Ok(true);
        }
        Ok(multi_miller_loop(&terms).final_exponentiation() == Gt::identity())
    }
}

/// `s·a + t·b` by one double-and-add over both scalars (Straus), with
/// `a + b` precomputed; nothing here is secret, so the walk is not
/// constant-time.
fn linear_combination(a: &G1Affine, s: &Scalar, b: &G1Affine, t: &Scalar) -> G1Projective {
    let ab = G1Affine::from(G1Projective::from(*a).add_mixed(b));
    let s = s.to_bytes();
    let t = t.to_bytes();
    let mut acc = G1Projective::identity();
    let mut started = false;
    for i in (0..256).rev() {
        if started {
            acc = acc.double();
        }
        let sb = (s[i / 8] >> (i % 8)) & 1 == 1;
        let tb = (t[i / 8] >> (i % 8)) & 1 == 1;
        match (sb, tb) {
            (true, true) => acc = acc.add_mixed(&ab),
            (true, false) => acc = acc.add_mixed(a),
            (false, true) => acc = acc.add_mixed(b),
            (false, false) => {}
        }
        started |= sb | tb;
    }
    acc
}

// ---------------------------------------------------------------------------
// modexp

/// `base^exp mod modulus` as big-endian bytes, at most `modulus.len()` of
/// them.  Operands of up to 256 bits run as a square-and-multiply ladder on
/// the uint256 multiplier; anything wider takes the generic implementation.
pub fn modexp(base: &[u8], exp: &[u8], modulus: &[u8]) -> Vec<u8> {
    #[cfg(target_os = "zkvm")]
    if base.len() <= 32 && modulus.len() <= 32 {
        return modexp256::modexp(base, exp, modulus);
    }
    aurora_engine_modexp::modexp(base, exp, modulus)
}

#[cfg(target_os = "zkvm")]
mod modexp256 {
    use zkm_lib::syscall_uint256_mulmod;

    type Words = [u32; 8];

    /// Big-endian bytes (at most 32) as little-endian words.
    fn words(be: &[u8]) -> Words {
        let mut padded = [0u8; 32];
        padded[32 - be.len()..].copy_from_slice(be);
        let mut w = [0u32; 8];
        for (i, word) in w.iter_mut().enumerate() {
            *word = u32::from_be_bytes(padded[28 - 4 * i..32 - 4 * i].try_into().expect("4 bytes"));
        }
        w
    }

    /// `(a · b) mod m` for `m ≠ 0`; the multiplier reads `b` and `m` as one
    /// 16-word block.
    fn mul_mod(a: &Words, b: &Words, m: &Words) -> Words {
        let mut x = *a;
        let mut bm = [0u32; 16];
        bm[..8].copy_from_slice(b);
        bm[8..].copy_from_slice(m);
        unsafe { syscall_uint256_mulmod(&mut x, bm.as_ptr().cast()) };
        x
    }

    pub fn modexp(base: &[u8], exp: &[u8], modulus: &[u8]) -> Vec<u8> {
        let m = words(modulus);
        if m == [0; 8] || m == [1, 0, 0, 0, 0, 0, 0, 0] {
            return Vec::new();
        }
        let b = mul_mod(&words(base), &[1, 0, 0, 0, 0, 0, 0, 0], &m);
        let mut r: Words = [1, 0, 0, 0, 0, 0, 0, 0];
        let mut started = false;
        for &byte in exp {
            for j in (0..8).rev() {
                if started {
                    r = mul_mod(&r, &r, &m);
                }
                if (byte >> j) & 1 == 1 {
                    r = mul_mod(&r, &b, &m);
                    started = true;
                }
            }
        }
        let mut out = [0u8; 32];
        for (i, word) in r.iter().enumerate() {
            out[28 - 4 * i..32 - 4 * i].copy_from_slice(&word.to_be_bytes());
        }
        out[32 - modulus.len()..].to_vec()
    }
}
