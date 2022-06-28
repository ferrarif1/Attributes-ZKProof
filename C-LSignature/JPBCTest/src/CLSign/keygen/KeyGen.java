package edu.jhu.isi.CLSign.keygen;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrElement;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import java.util.List;
import java.util.stream.Collectors;

public class KeyGen {
    /* step 3
    * Run the Setup algorithm to generate (q, G1, GT, g1, g2, e).
    * Choose x ← Zq, y ← Zq, and for 1 ≤ i ≤ l, zi ← Zq.
   *  Let X = g^x, Y = g^y and, for 1 ≤ i ≤ l, Zi = g^zi and Wi = Y^zi .
   *  Set sk = (x, y, z1,...,zl),
      pk = (q, G, G, g, g, e, X, Y, {Zi}, {Wi}).
    * */
    public static PublicKey createPublicKey(final Pairing pairing, final SecretKey sk) {
        final Element generator = pairing.getG1().newRandomElement().getImmutable();
        final Element generatorT = pairing.getGT().newRandomElement().getImmutable();
        final Element X = generator.powZn(sk.getX());
        final Element Y = generator.powZn(sk.getY());
        final List<Element> Z = sk.getZ().stream()
                .map(generator::powZn).collect(Collectors.toList());
        final List<Element> W = sk.getZ().stream()
                .map(Y::powZn).collect(Collectors.toList());
        return new PublicKey(pairing, generator, generatorT,
                X, Y, Z, W);
    }
   /* step 2
   *  sk = (x, y, z1,...,zl)
   * */
    public static SecretKey createSecretKey(final Pairing pairing, final int messageSize) {
        final ZrElement[] z = new ZrElement[messageSize];
        for (int i = 0; i < messageSize; i++) {
            z[i] = (ZrElement) pairing.getZr().newRandomElement().getImmutable();
        }
        return new SecretKey((ZrElement) pairing.getZr().newRandomElement().getImmutable(),
                (ZrElement) pairing.getZr().newRandomElement().getImmutable(), z);
    }
    //step 1
    public static Pairing createPairing() {
        int rBits = 160;
        int qBits = 512;

        final TypeACurveGenerator pairingGenerator = new TypeACurveGenerator(rBits, qBits);
        final PairingParameters params = pairingGenerator.generate();
        return PairingFactory.getPairing(params);
    }
}
