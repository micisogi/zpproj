import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.UserAttributePacket;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import utils.KeyRingHelper;
import utils.Utils;
import models.*;
import javax.crypto.spec.DHParameterSpec;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.util.Date;

public class DSAElGamalKeyRingGenerator {

    public void DSAElGamalKeyRingGenerator(){}
    public void generateDSAELGamalKeyRing(Integer dsaKeySize, Integer elGamalKeySize, String name,
                                          String email, String passPhrase)
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException, PGPException {
        KeyPairGenerator dsaKpg = KeyPairGenerator.getInstance("DSA", "BC");
        dsaKpg.initialize(dsaKeySize);
        KeyPair dsaKp = dsaKpg.generateKeyPair();

        KeyPairGenerator elgKpg = KeyPairGenerator.getInstance("ELGAMAL", "BC");
        BigInteger g = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
        BigInteger p = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);

        DHParameterSpec elParams = new DHParameterSpec(p, g);

        elgKpg.initialize(elParams);

        KeyPair elgKp = elgKpg.generateKeyPair();
        FileOutputStream outPublic = new FileOutputStream("D:\\exported_pub.asc");
        ArmoredOutputStream outSecret = new ArmoredOutputStream(new FileOutputStream("D:\\exported_secret.asc"));

        PGPKeyPair dsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKp, new Date());
        PGPKeyPair elgKeyPair = new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, elgKp, new Date());
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, dsaKeyPair,
                Utils.getInstance().formatNameAndEmail(name, email), sha1Calc, null, null, new JcaPGPContentSignerBuilder(dsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).setProvider("BC").build(passPhrase.toCharArray()));
        keyRingGen.addSubKey(elgKeyPair);
        PGPPublicKeyRing pkr = keyRingGen.generatePublicKeyRing();
        PGPSecretKeyRing skr = keyRingGen.generateSecretKeyRing();
        User user = new User(pkr.getPublicKey().getUserIDs().next());
        KeyRingHelper.getInstance().savePublicKeyRing(pkr);
        KeyRingHelper.getInstance().saveSecretKeyRing(skr);


    }


//   public  void generateDsaKeyPairWithParameters(Integer dsaKeySize, Integer elGamalKeySize,String name,String email) throws Exception, IOException, InvalidKeyException, NoSuchProviderException, SignatureException, PGPException {
//        Security.addProvider(new BouncyCastleProvider());
//        KeyPairGenerator dsaKpg = KeyPairGenerator.getInstance("DSA", "BC");
//        dsaKpg.initialize(1024);
//
//        KeyPair dsaKp = dsaKpg.generateKeyPair();
//
//        FileOutputStream secretOutputStream = new FileOutputStream("secret.asc");
//        FileOutputStream out2 = new FileOutputStream("pub.asc");
//        char[] zakucano = {'s', 'u', 's'};
//        KeyRingGenerator.exportKeyPair(secretOutputStream, out2, dsaKp, "LAZAR <hans.mueller@mail.com>", zakucano, "lazar@mojmail.com", 0);
//    }

}
