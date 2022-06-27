import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.math.BigInteger;

import static java.lang.System.clearProperty;
import static java.lang.System.out;

//EN文档http://gas.dia.unisa.it/projects/jpbc/index.html#.YrF1XexBzeI
//CH文档https://blank-vax.github.io/2021/07/05/%E5%9F%BA%E4%BA%8E%E9%85%8D%E5%AF%B9%E7%9A%84%E5%AF%86%E7%A0%81%E5%AD%A6%E2%80%94%E2%80%94%E5%9F%BA%E7%A1%80%E7%9F%A5%E8%AF%86%E5%8F%8AJPBC%E5%BA%93/
//视频https://www.bilibili.com/video/av456320837/?vd_source=6559bf26783d5592293dee7cfd9a8c75
//补充注意事项：https://blog.csdn.net/jingzi123456789/article/details/104945648
//https://blog.csdn.net/liuweiran900217/article/details/45080653?spm=1001.2014.3001.5501
public class JPBCDemoGroup {
    public static void main(String[] args){
        //Pairing参数：rBit是Zp中阶数p的比特长度，如160 qBit是G中阶数的比特长度，如512
        Pairing bp = PairingFactory.getPairing("a.properties");
        Field G1 = bp.getG1();
        Field G2 = bp.getG2();
        Field Zr = bp.getZr();//Zr - 有限域
        Field GT = bp.getGT();

        String m = "message";
        byte[] m_hash = Integer.toString(m.hashCode()).getBytes();
        //将byte[] m_hash哈希到Z_p群
        Element hash_Z_p = Zr.newElement().setFromHash(m_hash, 0, m_hash.length);
        //将byte[] m_hash哈希到G_1群
        Element hash_G_1 = G1.newElement().setFromHash(m_hash, 0, m_hash.length);
        //将byte[] m_hash哈希到G_2群
        Element hash_G_2 = G2.newElement().setFromHash(m_hash, 0, m_hash.length);
        //将byte[] m_hash哈希到G_T群
        Element hash_G_T = GT.newElement().setFromHash(m_hash, 0, m_hash.length);
        out.println("hash_Z_p "+hash_Z_p);
        out.println("hash_G_1 "+hash_G_1);
        out.println("hash_G_2 "+hash_G_2);
        out.println("hash_G_T "+hash_G_T);


        //测试Zr有限域的加法和乘法
        out.println("测试Zr有限域的加法和乘法");
        Element x = Zr.newOneElement().getImmutable();
        Element y = Zr.newElement(4).getImmutable();
        out.println("x = " + x + " y = " + y);
        out.println(x.add(y));
        out.println(x.mul(y));
        out.println(x.div(y));
        out.println(x.sub(y));


        //测试椭圆曲线群加法乘法
        out.println("测试椭圆曲线群加法乘法");
        Element g1 = G1.newRandomElement().getImmutable();
        Element g2 = G1.newRandomElement().getImmutable();

        out.println("g1+g2 = "+g1.add(g2));
        out.println("g1*g2 = "+g1.mul(g2));

        out.println("g1*2 = "+g1.mul(new BigInteger("2")));
        out.println("g1^2 = "+g1.pow(new BigInteger("2")));

        //按加法群： g1^3 两者应相等
        out.println("按加法群：两者应相等:");
        Element a = Zr.newElement(3);
        out.println("g1+g1+g1 = " + g1.add(g1).add(g1));
        out.println("g1*a = " + g1.mulZn(a));
        //按乘法群: 两者应相等 注意用的是mul(),不是mulZn()
        out.println("按乘法群: 两者应相等:");
        out.println("g1*g1*g1 = " + g1.mul(g1).mul(g1));
        out.println("g1^a = " + g1.powZn(a));

        //测试群的阶
        out.println("测试群的阶:");
        BigInteger r = G1.getOrder();
        out.println(r);
        //g^r = 单位元
        Element g = G1.newRandomElement().getImmutable();
        out.println("当作乘法群 "+ g.pow(r).isOne());
        out.println("当作加法群 "+ g.pow(r).isZero());

        out.println("newOneElement = "+ G1.newOneElement());
        out.println("newZeroElement = "+ G1.newZeroElement());


        //执行时间问题
        long startTime = System.currentTimeMillis();
        float repeatNum = 100;
        for(int i = 0;i < repeatNum; i++){
            bp.pairing(g1, g2);
        }
        out.println((System.currentTimeMillis() - startTime)/repeatNum);

        Element x1 = Zr.newRandomElement().getImmutable();
        startTime = System.currentTimeMillis();
        for(int i = 0;i < repeatNum; i++){
            g1.powZn(x1);
        }
        out.println((System.currentTimeMillis() - startTime)/repeatNum);


        //存储空间问题
        Element g3 = G1.newRandomElement().getImmutable();
        out.println("椭圆曲线上点两个元素 各64bytes ：" + g3.getLengthInBytes());

        Element x3 = Zr.newRandomElement().getImmutable();
        out.println("Zr有限域 r是 160 Bits，故其元素为 20 Bytes：" + x3.getLengthInBytes());

        Element gt3 = GT.newRandomElement().getImmutable();
        out.println("GT上点两个元素 各64bytes ：" + gt3.getLengthInBytes());


    }
}
