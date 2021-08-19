import models.User;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import utils.KeyRingHelper;
import utils.Utils;

import javax.crypto.spec.DHParameterSpec;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.util.Date;

public class DSAElGamalKeyRingGenerator {

    public void DSAElGamalKeyRingGenerator() {
    }

    public void generateDSAELGamalKeyRing(Integer dsaKeySize, Integer elGamalKeySize, String name,
                                          String email, String passPhrase)
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException, PGPException {
        KeyPairGenerator dsaKpg = KeyPairGenerator.getInstance("DSA", "BC");
        dsaKpg.initialize(dsaKeySize);
        KeyPair dsaKp = dsaKpg.generateKeyPair();

        KeyPairGenerator elgKpg = KeyPairGenerator.getInstance("ELGAMAL", "BC");
        BigInteger g = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
        BigInteger p = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);

        DHParameterSpec elParams = new DHParameterSpec(p, g, elGamalKeySize);

        elgKpg.initialize(elParams);

        KeyPair elgKp = elgKpg.generateKeyPair();
        PGPKeyPair dsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKp, new Date());
        PGPKeyPair elgKeyPair = new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, elgKp, new Date());
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, dsaKeyPair,
                Utils.getInstance().formatNameAndEmail(name, email), sha1Calc, null, null, new JcaPGPContentSignerBuilder(dsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).setProvider("BC").build(passPhrase.toCharArray()));
        keyRingGen.addSubKey(elgKeyPair);
        PGPPublicKeyRing pkr = keyRingGen.generatePublicKeyRing();
        PGPSecretKeyRing skr = keyRingGen.generateSecretKeyRing();
        User u = new User(Utils.getInstance().formatNameAndEmail(name, email));
        u.setPassword(passPhrase);
        u.setPubKeyRing(pkr);
        u.setSecKeyRing(skr);

        KeyRingHelper.getInstance().savePublicKeyRing(pkr);
        KeyRingHelper.getInstance().saveSecretKeyRing(skr);


    }
}
