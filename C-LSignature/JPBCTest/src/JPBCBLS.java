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
      *BLS聚合签名
      * 区块链应用场景下，通常用于压缩区块内交易的签名大小，假设我们有一个包含10笔交易的区块，每笔交易i有自己的签名S_iSi、公钥P_iPi以及一个签名消息为m_imi。
        聚合签名是将区块中所有交易签名的打包成一个签名，同时验证所有交易的签名正确性。
        令最终签名结果为S,
        S =S_1 +S_2 + ... +S_{10}S=S1+S2+...+S10
       要验证区块所有交易签名，需检查下式成立：
        e(G, S) = e(P_1,q_1)*e(P_2,q_2)...*e(P_{10},q_{10})e(G,S)=e(P1,q1)∗e(P2,q2)...∗e(P10,q10)
       推导如下：
       e(G, S)=e(G,S_1 +S_2 + ... +S_{10})e(G,S)=e(G,S1+S2+...+S10)
       =e(G, S_1)*e(G, S_2)*...*e(G, S_{10})=e(G,S1)∗e(G,S2)∗...∗e(G,S10)
       =e(G,pk_1*q_1)*...*e(G,pk_{10}*q_{10})=e(G,pk1∗q1)∗...∗e(G,pk10∗q10)
       =e(pk_1*G,q_1)*...*e(pk_{10}*G,q_{10})=e(pk1∗G,q1)∗...∗e(pk10∗G,q10)
       =e(P_1,q_1)*e(P_2,q_2)...e(P_{10},q_{10})=e(P1,q1)∗e(P2,q2)...e(P10,q10)

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
