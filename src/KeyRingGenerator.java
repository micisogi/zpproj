import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.Date;

public class KeyRingGenerator {
    public static void exportKeyPair(
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
