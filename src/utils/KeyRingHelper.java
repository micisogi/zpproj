package utils;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;


public class KeyRingHelper {

    public static String PUBLIC_KEY_RING_COLLECTION_FILE_PATH = "pbkc.dat";
    public static String SECRET_KEY_RING_COLLECTION_FILE_PATH = "sckc.dat";

    private static KeyRingHelper instance;

    private KeyRingHelper() throws IOException {
        File tmpDirPubKeyCollection = new File(PUBLIC_KEY_RING_COLLECTION_FILE_PATH);
        boolean existsPublicKeyCollection = tmpDirPubKeyCollection.exists();
        File tmpDirSecretKeyCollection = new File(SECRET_KEY_RING_COLLECTION_FILE_PATH);
        boolean existsSecretKeyCollection = tmpDirSecretKeyCollection.exists();

        if (!existsPublicKeyCollection) {
            FileOutputStream fosPublic = new FileOutputStream(PUBLIC_KEY_RING_COLLECTION_FILE_PATH);
            System.out.println("FOS PUB BEFORE FLUSH");
            fosPublic.flush();
            fosPublic.close();
        }
        if (!existsSecretKeyCollection) {
            FileOutputStream fosSecret = new FileOutputStream(SECRET_KEY_RING_COLLECTION_FILE_PATH);
            System.out.println("FOS SEC BEFORE FLUSH");
            fosSecret.flush();
            fosSecret.close();
        }
    }

    public static KeyRingHelper getInstance() throws IOException {
        if (instance == null) {
            synchronized (KeyRingHelper.class) {
                if (instance == null) {
                    instance = new KeyRingHelper();
                }
            }
        }
        return instance;
    }

    public Iterator<PGPPublicKeyRing> savePublicKeyRing(PGPPublicKeyRing pgpPublicKeyRing) {
        try (FileInputStream keyInputStream = new FileInputStream(PUBLIC_KEY_RING_COLLECTION_FILE_PATH)) {
            PGPPublicKeyRingCollection pgpPubCollection = new PGPPublicKeyRingCollection(
                    PGPUtil.getDecoderStream(keyInputStream), new JcaKeyFingerprintCalculator());
            pgpPubCollection = PGPPublicKeyRingCollection.addPublicKeyRing(pgpPubCollection, pgpPublicKeyRing);
            byte myEncoded[] = pgpPubCollection.getEncoded();
            try (FileOutputStream fos = new FileOutputStream(PUBLIC_KEY_RING_COLLECTION_FILE_PATH)) {
                fos.write(myEncoded);
            }
            return pgpPubCollection.iterator();

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public List<PGPPublicKey> getPublicKeyRingsFromFile() {
        ArrayList<PGPPublicKey> pgpPublicKeyList = new ArrayList<>();
        try (FileInputStream keyInputStream = new FileInputStream(PUBLIC_KEY_RING_COLLECTION_FILE_PATH)) {
            PGPPublicKeyRingCollection pgpPubCollection = new PGPPublicKeyRingCollection(
                    PGPUtil.getDecoderStream(keyInputStream), new JcaKeyFingerprintCalculator());
            Iterator keyRingIter = pgpPubCollection.getKeyRings();
            while (keyRingIter.hasNext()) {
                PGPPublicKeyRing keyRing = (PGPPublicKeyRing) keyRingIter.next();

                Iterator keyIter = keyRing.getPublicKeys();
                while (keyIter.hasNext()) {
                    PGPPublicKey key = (PGPPublicKey) keyIter.next();
                    pgpPublicKeyList.add(key);
                }
            }
            return pgpPublicKeyList;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
