package edu.jhu.isi.CLSign.proof;

import edu.jhu.isi.CLSign.keygen.PublicKey;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrElement;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Prover {
    /* Scheme D：
    * Prover’s input. The block of messages (m(0),...,m(l)) and
    * signature σ = (a, {Ai}, b, {Bi}, c).
    *
    * Protocol. The prover does the following:
    1. Compute a blinded version of his signature σ: Choose random r, r' ∈ Zq.
    Form σ˜ = (a˜, {Ai˜}, b˜, {Bi˜}, c˜) as follows:
    a˜ = a^r, ˜b = b^r and ˜c = c^r A˜i = Ai^r and B˜i = Bi^r
    * for 1 ≤ i ≤ l
    Further, blind c˜ to obtain a value c˜ that it is distributed independently
    of everything else: cˆ = c˜^r'.
    Send (a˜, {Ai˜}, b˜, {Bi˜}, cˆ) to the verifier.
    2. Let vx, vxy, V(xy,i), i = 1,...,l, and vs be as follows:
    vx = e(X, a˜) , vxy = e(X, b˜) , V(xy,i) = e(X, Bi˜) , vs = e(g, cˆ)
    * The Prover and Verifier compute these values (locally) and then carry
    out the following zero-knowledge proof protocol:
    PK{(µ(0),...,µ(l), ρ):(vs)^ρ = vx * (vxy)^µ(0) * 累乘(i=1->i=l)[V(xy,i)^µ(i)]}

    * The Verifier accepts if it accepts the proof above and:
    * (a) {Ai˜} were formed correctly: e(a˜, Zi) = e(g, Ai˜);
    * (b) b˜ and {Bi˜} were formed correctly:
    *     e(a˜, Y) = e(g, b˜)
    *     e(Ai˜, Y) = e(g, Bi˜)
    * The protocol above is a zero knowledge proof of knowledge of a
    signature σ on a block of messages (m(0),...,m(l)) under Signature Scheme D.
    * */
    public static List<Element> computeProof(final List<Element> t, final List<ZrElement> messages, final Element challenge) {
        final List<Element> s = new ArrayList<>();
        for (int i = 0; i < t.size(); i++) {
            s.add(messages.get(i).mul(challenge).add(t.get(i)));
        }
        return s;
    }

    public static Element computeProofComm(final PublicKey pk, final List<Element> t, final int size) {
        t.add(pk.getPairing().getZr().newRandomElement());
        Element proofComm = pk.getGenerator().powZn(t.get(0));
        for (int i = 1; i < size; i++) {
            t.add(pk.getPairing().getZr().newRandomElement());
            proofComm = proofComm.mul(pk.getZ(i).powZn(t.get(i)));
        }
        return proofComm;
    }

    public static Element computeChallenge(final Element commitment, final Element proofComm, final PublicKey pk) {
        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
            final byte[] hash = digest.digest((Arrays.toString(proofComm.toBytes()) +
                    Arrays.toString(commitment.toBytes())).getBytes());
            return pk.getPairing().getZr().newElementFromBytes(hash);
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static boolean verify(final Element commitment, final Proof proof, final PublicKey pk) {
        Element lhs = pk.getGenerator().powZn(proof.getOpenings().get(0));
        for (int i = 1; i < proof.getOpenings().size(); i++) {
            lhs = lhs.mul(pk.getZ(i).powZn(proof.getOpenings().get(i)));
        }
        final Element rhs = commitment.powZn(computeChallenge(commitment, proof.getCommitment(), pk)).mul(proof.getCommitment());
        return lhs.equals(rhs);
    }
}
//*Scheme C:
//1.Key generation
//Run the Setup algorithm to generate (q, G1, GT, g, g, e). Choose
// x ← Zq, y ← Zq, and for 1 ≤ i ≤ l, zi ← Zq.
// Let X = g^x, Y = g^y and, for 1 ≤ i ≤ l, Zi = g^zi .
// Set sk = (x, y, z1,...,zl), pk = (q, G1, GT, g1, gt, e, X, Y, {Zi}).
//2.Signature
//On input message (m(0), m(1),...,m(l)),
// sk = (x, y,z1,...,zl) pk = (q, G1, GT, g1, gt, e, X, Y, {Zi}) do:
//– Choose a random a ← G.
//– Let Ai = a^zi for 1 ≤ i ≤ l.
//– Let b = a^y, Bi = (Ai)^y.
//– Let c = a^(x+xym(0)) * 累乘(i=1->i=l)[Ai^xym(i)]
//Output σ = (a, {Ai}, b, {Bi}, c)
//3.Verification
//On input pk, message (m(0),...,m(l)), and signature σ = (a, {Ai}, b, {Bi}, c),
// check the following:
//1. {Ai} were formed correctly: e(a, Zi) = e(g, Ai).
//2. b and {Bi} were formed correctly:
//   e(a, Y) = e(g, b)
//   e(Ai, Y) = e(g, Bi).
//3. c was formed correctly:
// e(X, a) * e(X, b)^m(0) * 累乘(i=1->i=l)[e(X, Bi)^m(i)] = e(g, c)
//*********************************************************************************************************************
//Obtaining a Signature C on a Committed Value:
//Suppose that M = g^m(0)*累乘(i=1->i=l)[Zi^m(i)] is a commitment to a set of messages
// (m(0),...,m(l)) whose signature the user wishes to obtain.
// Then the user and the signer run the following protocol:
//1.Common Input. The public key pk = (q, G1, GT, g1, gt, e, X, Y, {Zi}), and a commitment M.
//2.User’s Input. Values m(0),...,m(l) such that M = g^m(0)*累乘(i=1->i=l)[Zi^m(i)]
//3.Signer’s Input. Signing key sk = (x, y, {zi}).
//4.Protocol. First, the user gives a zero-knowledge proof of knowledge of the opening of the commitment:
//PK{(µ(0),...,µ(l)) : M = g^µ(0) * 累乘(i=1->i=l)[Zi^µ(i)]}
//Next, the signer computes σ = (a, {Ai}, b, {Bi}, c) as described above, namely:
//– α ← Zq, a = g^α.
//– For 1 ≤ i ≤ l, let Ai = a^zi . Then set b = a^y, and
//  for 1 ≤ i ≤ l, let Bi = Ai^y
//– c = a^x*M^(αxy).
//The user outputs the signature σ
// */