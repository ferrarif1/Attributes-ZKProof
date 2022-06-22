import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import static java.lang.System.out;

public class JPBCBLS {
    //BLS Signature
    /*
    * Init:
    * 1.生成pairing参数PK = <G1,GT,Zr,g,e>
      2.选取随机数x属于Zr作为私钥
      3.计算对应的公钥pk = g^x
      *
      Sign:
      * 签名者将消息m的哈希值映射为一个G1上的群元素h，
      * 并利用私钥计算签名sig = h^x
      Verify:
      * 验证者拥有m，sig，pk ,PK
      * 验证e(sig,g) ?= e(h,g^x)
      * 即  e(h^x,g) ?= e(h,g^x)
    * */
    public static void main(String[] args){
        //Initialiaztion
        Pairing bp = PairingFactory.getPairing("a.properties");
        Field G1 = bp.getG1();
        Field Zr = bp.getZr();
        Element g = G1.newRandomElement().getImmutable();
        Element x = Zr.newOneElement().getImmutable();
        Element g_x = g.duplicate().powZn(x);

        //Signing
        String m = "message";
        byte[] m_hash = Integer.toString(m.hashCode()).getBytes();
        Element h = G1.newElementFromHash(m_hash, 0,m_hash.length);
        Element sig = h.duplicate().powZn(x);

        //Verification
        Element pl = bp.pairing(g, sig);
        Element pr = bp.pairing(h,g_x);
        if(pl.isEqual(pr)){
            out.println("YES");
        }else {
            out.println("NO");
        }


    }
}
