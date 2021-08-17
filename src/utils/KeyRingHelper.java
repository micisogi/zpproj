package utils;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Iterator;


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

    public Iterator<PGPPublicKeyRing> savePublicKeyRing(PGPPublicKeyRing pgpPublicKeyRing) throws IOException, PGPException {
        try (FileInputStream keyInputStream = new FileInputStream(PUBLIC_KEY_RING_COLLECTION_FILE_PATH)) {

            PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
                    PGPUtil.getDecoderStream(keyInputStream), new JcaKeyFingerprintCalculator());
            PGPPublicKeyRingCollection.addPublicKeyRing(pgpPub, pgpPublicKeyRing);
            byte myEncoded[] = pgpPub.getEncoded();
            try (FileOutputStream fos = new FileOutputStream(PUBLIC_KEY_RING_COLLECTION_FILE_PATH)) {
                System.out.println("INSIDE TRY MY ENCODED"+myEncoded);
                fos.write(myEncoded);
            }
            try(FileInputStream fis= new FileInputStream(PUBLIC_KEY_RING_COLLECTION_FILE_PATH)){
                System.out.println("INSIDE SCOND TRY ");
                int ch;
                while ((ch = fis.read()) != -1) {
                    System.out.print((char) ch);
                }
            }
            return pgpPub.iterator();

        }
    }

//    public List<PGPPublicKeyRing> getPublicKeyRingsFromFile() {
//        ArrayList<PGPPublicKeyRing> pgpPublicKeyRings = new ArrayList<>();
//        for ()
//    }
}
