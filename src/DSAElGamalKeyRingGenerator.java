import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;

public class DSAElGamalKeyRingGenerator {
   public  void generateDsaKeyPairWithParameters(Integer dsaKeySize, Integer elGamalKeySize,String name,String email) throws Exception, IOException, InvalidKeyException, NoSuchProviderException, SignatureException, PGPException {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator dsaKpg = KeyPairGenerator.getInstance("DSA", "BC");
        dsaKpg.initialize(1024);

        KeyPair dsaKp = dsaKpg.generateKeyPair();

        FileOutputStream secretOutputStream = new FileOutputStream("secret.asc");
        FileOutputStream out2 = new FileOutputStream("pub.asc");
        char[] zakucano = {'s', 'u', 's'};
        KeyRingGenerator.exportKeyPair(secretOutputStream, out2, dsaKp, "LAZAR <hans.mueller@mail.com>", zakucano, "lazar@mojmail.com", 0);
    }


}
