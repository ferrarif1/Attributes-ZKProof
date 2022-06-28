/*
 * Copyright (c) 2016 Gijs Van Laer
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package edu.jhu.isi.CLSign;

import edu.jhu.isi.CLSign.keygen.KeyGen;
import edu.jhu.isi.CLSign.keygen.KeyPair;
import edu.jhu.isi.CLSign.keygen.PublicKey;
import edu.jhu.isi.CLSign.keygen.SecretKey;
import edu.jhu.isi.CLSign.proof.Proof;
import edu.jhu.isi.CLSign.proof.Prover;
import edu.jhu.isi.CLSign.sign.Sign;
import edu.jhu.isi.CLSign.sign.Signature;
import edu.jhu.isi.CLSign.verify.Verify;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrElement;

import java.util.ArrayList;
import java.util.List;

//*Scheme C:签名一组消息
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
//Obtaining a Signature C on a Committed Value:签名一组消息的承诺
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

 /* Scheme D：零知识证明方案C的签名
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

public class CLSign {
    public static KeyPair keyGen(final int messageSize) {
        final Pairing pairing = KeyGen.createPairing();
        final SecretKey sk = KeyGen.createSecretKey(pairing, messageSize);
        final PublicKey pk = KeyGen.createPublicKey(pairing, sk);
        return new KeyPair(pk, sk);
    }

    public static Element commit(final List<ZrElement> messages, final PublicKey pk) {
        if (messages.size() != pk.getZ().size()) {
            throw new IllegalStateException("Public key should be generated with the correct message size");
        }
        return doCommit(messages, pk);
    }

    public static Element partialCommit(final List<ZrElement> messages, final PublicKey pk) {
        if (messages.size() > pk.getZ().size()) {
            throw new IllegalStateException("Public key should be generated with a larger message size");
        }
        return doCommit(messages, pk);
    }

    public static Proof proofCommitment(final Element commitment, final List<ZrElement> messages, final PublicKey pk) {
        final List<Element> t = new ArrayList<>();
        //proofComm = g^t0 * 累乘(i=1->i=l)[zi^ti]
        //t ={ti} - random from Zn
        final Element proofComm = Prover.computeProofComm(pk, t, messages.size());
        final Element challenge = Prover.computeChallenge(commitment, proofComm, pk);
        //s = {mi*challenge+ti}
        final List<Element> s = Prover.computeProof(t, messages, challenge);

        return new Proof(proofComm, s);
    }

    public static Signature sign(final List<ZrElement> messages, final KeyPair keys) {
        final Element commitment = commit(messages, keys.getPk());
        return Sign.sign(commitment, keys);
    }

    public static Signature signBlind(final Element commitment, final Proof proof, final KeyPair keys) {
        if (!Prover.verify(commitment, proof, keys.getPk())) {
            return null;
        }
        return Sign.sign(commitment, keys);
    }

    public static Signature signPartiallyBlind(final List<ZrElement> messages, final Element commitment, final Proof proof, final KeyPair keys) {
        if (!Prover.verify(commitment, proof, keys.getPk())) {
            return null;
        }
        final List<Element> Z = keys.getPk().getZ();
        final List<Element> subKey = Z.subList(Z.size() - messages.size(), Z.size());
        final Element extendCommitment = keys.getPk().getPairing().getG1().newOneElement();
        for (int i = 0; i < messages.size(); i++) {
            extendCommitment.mul(subKey.get(i).powZn(messages.get(i)));
        }
        return Sign.sign(commitment.mul(extendCommitment), keys);
    }


    public static boolean verify(final List<ZrElement> messages, final Signature sigma, final PublicKey pk) {
        return Verify.aFormedCorrectly(sigma, pk)
                && Verify.bFormedCorrectly(sigma, pk)
                && Verify.cFormedCorrectly(messages, sigma, pk);
    }

    /*
    * commitment => 论文中的M
    * commitment = g^m0 * 累乘[zi^mi]
    * */
    private static Element doCommit(final List<ZrElement> messages, final PublicKey pk) {
        Element commitment = pk.getGenerator().powZn(messages.get(0));
        for (int i = 1; i < messages.size(); i++) {
            commitment = commitment.mul(pk.getZ(i).powZn(messages.get(i)));
        }
        return commitment.getImmutable();
    }
}
