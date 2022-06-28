package edu.jhu.isi.CLSign.proof;

import edu.jhu.isi.CLSign.keygen.PublicKey;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrElement;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Prover {
    /*
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
