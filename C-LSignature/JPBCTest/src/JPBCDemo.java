import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import javax.tools.StandardJavaFileManager;
//EN文档http://gas.dia.unisa.it/projects/jpbc/index.html#.YrF1XexBzeI
//CH文档https://blank-vax.github.io/2021/07/05/%E5%9F%BA%E4%BA%8E%E9%85%8D%E5%AF%B9%E7%9A%84%E5%AF%86%E7%A0%81%E5%AD%A6%E2%80%94%E2%80%94%E5%9F%BA%E7%A1%80%E7%9F%A5%E8%AF%86%E5%8F%8AJPBC%E5%BA%93/
//视频https://www.bilibili.com/video/av456320837/?vd_source=6559bf26783d5592293dee7cfd9a8c75

public class JPBCDemo {
    public static void main(String[] args){
        Pairing bp = PairingFactory.getPairing("a.properties");
        Field G1 = bp.getG1();
        Field Zr = bp.getZr();//Zr - 有限域
        //使用getImmutable()会使得g后续不可变
        Element g = G1.newRandomElement().getImmutable();
        Element a = Zr.newRandomElement();
        System.out.println(g);
        Element b = Zr.newRandomElement();

        Element g_a = g.duplicate().powZn(a);
        //如果不用.duplicate()，则g会改变,使用getImmutable()也可以
        System.out.println(g);
        System.out.println(g_a);
        Element g_b = g.duplicate().powZn(b);
        Element egg_ab = bp.pairing(g_a, g_b);

        Element egg = bp.pairing(g, g);
        Element ab = a.duplicate().mul(b);
        Element egg_ab_p = egg.duplicate().powZn(ab);

        //验证配对e(g^a,g^b) = e(g,g)^ab
        if(egg_ab_p.isEqual(egg_ab)){
            System.out.println("YES");
        }else {
            System.out.println("NO");
        }




    }
}
