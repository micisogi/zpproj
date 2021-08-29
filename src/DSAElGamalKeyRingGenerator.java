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
import java.security.*;
import java.security.spec.InvalidParameterSpecException;
import java.util.Date;

public class DSAElGamalKeyRingGenerator {

    public void generateDSAELGamalKeyRing(Integer dsaKeySize, Integer elGamalKeySize, String name,
                                          String email, String passPhrase)
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException, PGPException {
        KeyPairGenerator dsaKpg = KeyPairGenerator.getInstance("DSA", "BC");
        dsaKpg.initialize(dsaKeySize);
        KeyPair dsaKp = dsaKpg.generateKeyPair();


        KeyPair elgKp = generateElGamalKeyPair(elGamalKeySize);
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

    private KeyPair generateElGamalKeyPair(Integer elGamalKeySize) {
        KeyPairGenerator elgKpg = null;
        try {
            elgKpg = KeyPairGenerator.getInstance("ELGAMAL", "BC");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }

        AlgorithmParameterGenerator a = null;
        try {
            a = AlgorithmParameterGenerator.getInstance("ElGamal", "BC");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        a.init(elGamalKeySize, new SecureRandom());
        AlgorithmParameters params = a.generateParameters();
        try {
            DHParameterSpec elP = (DHParameterSpec) params.getParameterSpec(DHParameterSpec.class);
            elgKpg.initialize(elP);
            return elgKpg.generateKeyPair();
        } catch (InvalidParameterSpecException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;
    }
}
