import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.io.pem.PemObjectParser;

import java.io.*;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.Date;
import java.util.Iterator;

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

    static PGPPublicKey readPublicKey(String fileName) throws IOException, PGPException {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
        PGPPublicKey pubKey = readPublicKey(keyIn);
        keyIn.close();
        return pubKey;
    }

    static PGPPublicKey readPublicKey(InputStream input) throws IOException, PGPException {
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());
        byte myEncoded[] = pgpPub.getEncoded();
        try (FileOutputStream fos = new FileOutputStream("pbk")) {
            fos.write(myEncoded);
        }

        //
        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //
        Iterator keyRingIter = pgpPub.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing) keyRingIter.next();
            System.out.println(keyRing.iterator().next().getUserIDs().next());
            Iterator keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext()) {
                PGPPublicKey key = (PGPPublicKey) keyIter.next();
                if (key.isEncryptionKey()) {
                    System.out.println(Long.toHexString(key.getKeyID()));
                    return key;
                }
            }
        }
        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }

    static void insertKeyRing(PGPPublicKeyRing pgpPublicKeyRing, PGPPublicKeyRingCollection pgpPub) {
        Iterator keyRingIter = pgpPub.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing) keyRingIter.next();
            System.out.println(keyRing.iterator().next().getUserIDs().next());
            Iterator keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext()) {
                PGPPublicKey key = (PGPPublicKey) keyIter.next();
                if (key.isEncryptionKey()) {
                    System.out.println(Long.toHexString(key.getKeyID()));
                }
            }
        }
    }
}
