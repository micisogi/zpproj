import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.*;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.*;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

public class DSAKeyRingGenerator {
   public  void generateDsaKeyPair(Integer keysize) throws Exception, IOException, InvalidKeyException, NoSuchProviderException, SignatureException, PGPException {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator dsaKpg = KeyPairGenerator.getInstance("DSA", "BC");
        dsaKpg.initialize(keysize);

        KeyPair dsaKp = dsaKpg.generateKeyPair();

        FileOutputStream secretOutputStream = new FileOutputStream("secret.asc");
        FileOutputStream out2 = new FileOutputStream("pub.asc");
        char[] zakucano = {'s', 'u', 's'};
        exportKeyPair(secretOutputStream, out2, dsaKp, "LAZAR <hans.mueller@mail.com>", zakucano, "lazar@mojmail.com", 0);
    }

    private static void exportKeyPair(
            OutputStream secretOut,
            OutputStream publicOut,
            KeyPair keyPair,
            String identity,
            char[] passPhrase,
            String email,
            int algType) throws Exception, IOException, InvalidKeyException, NoSuchProviderException, SignatureException, PGPException {
        secretOut = new ArmoredOutputStream(secretOut);
        PGPKeyPair pgpKeyPair;
        if (algType == 0) {
            pgpKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, keyPair, new Date());
        } else {
            pgpKeyPair = new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, keyPair, new Date());
        }

        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);

        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, pgpKeyPair,
                identity, sha1Calc, null, null, new JcaPGPContentSignerBuilder(pgpKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).setProvider("BC").build(passPhrase));

        keyRingGen.generateSecretKeyRing().encode(secretOut);
        secretOut.close();
        keyRingGen.generatePublicKeyRing().encode(publicOut);
        publicOut.close();
    }
}
