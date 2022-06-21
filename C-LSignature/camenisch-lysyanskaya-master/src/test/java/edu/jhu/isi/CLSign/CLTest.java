package edu.jhu.isi.CLSign;

import edu.jhu.isi.CLSign.keygen.KeyPair;
import edu.jhu.isi.CLSign.keygen.PublicKey;
import edu.jhu.isi.CLSign.keygen.SecretKey;
import edu.jhu.isi.CLSign.proof.Proof;
import edu.jhu.isi.CLSign.sign.Signature;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrElement;
import org.junit.Test;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class CLTest {
    // KeyGen
    final int messageSize = 5;
    final KeyPair keyPair = CLSign.keyGen(messageSize);
    final PublicKey pk = keyPair.getPk();
    final SecretKey sk = keyPair.getSk();

    // sign
    final int messageSize = 5;
    final KeyPair keyPair = CLSign.keyGen(messageSize);
    final List<ZrElement> messages = IntStream.range(0, messageSize)
            .mapToObj(i -> (ZrElement) keyPair.getPk().getPairing().getZr().newRandomElement().getImmutable())
            .collect(Collectors.toList());
    final Signature sigma = CLSign.sign(messages, keyPair);

    // verify
    final int messageSize = 5;
    final KeyPair keyPair = CLSign.keyGen(messageSize);
    final List<ZrElement> messages = IntStream.range(0, messageSize)
            .mapToObj(i -> (ZrElement) keyPair.getPk().getPairing().getZr().newRandomElement().getImmutable())
            .collect(Collectors.toList());
    final Signature sigma = CLSign.sign(messages, keyPair);

}
