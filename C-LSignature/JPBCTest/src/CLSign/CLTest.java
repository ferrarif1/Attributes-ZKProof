package CLSign;

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
import static java.lang.System.out;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
/*
Scheme D in this paper:
Signature Schemes and Anonymous Credentialsfrom Bilinear Maps
 */
public class CLTest {
    // KeyGen
    final int messageSize = 5;
    final KeyPair keyPair1 = CLSign.keyGen(messageSize);
    final PublicKey pk = keyPair1.getPk();
    final SecretKey sk = keyPair1.getSk();

    // sign
    final KeyPair keyPair2 = CLSign.keyGen(messageSize);
    //messages2 -> Zr.newRandomElement
    final List<ZrElement> messages2 = IntStream.range(0, messageSize)
            .mapToObj(i -> (ZrElement) keyPair2.getPk().getPairing().getZr().newRandomElement().getImmutable())
            .collect(Collectors.toList());
    final Signature sigma2 = CLSign.sign(messages2, keyPair2);
    ZrElement m0 = messages2.get(0);
    System.out.println(m0);
    //out.println("messages2: "+ sigma2);


    // verify
    final KeyPair keyPair3 = CLSign.keyGen(messageSize);
    final List<ZrElement> messages3 = IntStream.range(0, messageSize)
            .mapToObj(i -> (ZrElement) keyPair3.getPk().getPairing().getZr().newRandomElement().getImmutable())
            .collect(Collectors.toList());
    final Signature sigma3 = CLSign.sign(messages3, keyPair3);

}
