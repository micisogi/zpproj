package utils;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import java.io.*;
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

    public Iterator<PGPSecretKeyRing> saveSecretKeyRing(PGPSecretKeyRing pgpSecretKeyRing) {
        try (FileInputStream keyInputStream = new FileInputStream(SECRET_KEY_RING_COLLECTION_FILE_PATH)) {
            PGPSecretKeyRingCollection pgpSecCollection = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(keyInputStream), new JcaKeyFingerprintCalculator());
            pgpSecCollection = PGPSecretKeyRingCollection.addSecretKeyRing(pgpSecCollection, pgpSecretKeyRing);
            byte myEncoded[] = pgpSecCollection.getEncoded();
            try (FileOutputStream fos = new FileOutputStream(SECRET_KEY_RING_COLLECTION_FILE_PATH)) {
                fos.write(myEncoded);
            }
            return pgpSecCollection.iterator();

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        }
        return null;
    }


    public Iterator<PGPPublicKeyRing> savePublicKeyRing(PGPPublicKeyRing pgpPublicKeyRing) {
        try (FileInputStream keyInputStream = new FileInputStream(PUBLIC_KEY_RING_COLLECTION_FILE_PATH)) {
            PGPPublicKeyRingCollection pgpPubCollection = new PGPPublicKeyRingCollection(
                    PGPUtil.getDecoderStream(keyInputStream), new JcaKeyFingerprintCalculator());
            pgpPubCollection = PGPPublicKeyRingCollection.addPublicKeyRing(pgpPubCollection, pgpPublicKeyRing);
            for (PGPPublicKey pk : pgpPubCollection.iterator().next()) {
                System.out.println("ID: " + pk.getKeyID());
            }
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

    public void deleteKeyRing(String keyRingIdHexa) {
        try (FileInputStream keyInputStream = new FileInputStream(PUBLIC_KEY_RING_COLLECTION_FILE_PATH)) {
            PGPPublicKeyRingCollection pgpPubCollection = new PGPPublicKeyRingCollection(
                    PGPUtil.getDecoderStream(keyInputStream), new JcaKeyFingerprintCalculator());
            long keyId = Utils.getInstance().hexStringToLongID(keyRingIdHexa);
            PGPPublicKeyRing keyRing = pgpPubCollection.getPublicKeyRing(keyId);
            System.out.println("BEFORE: " + pgpPubCollection.size());
            if (checkIfPublicKeyRingWithIdExists(keyId, pgpPubCollection)) {
                pgpPubCollection = PGPPublicKeyRingCollection.removePublicKeyRing(pgpPubCollection, keyRing);
            }
            removeSecretKey(keyId);
            System.out.println("AFTER: " + pgpPubCollection.size());
            if (pgpPubCollection.iterator().hasNext()) {
                for (PGPPublicKey pk : pgpPubCollection.iterator().next()) {
                    System.out.println("ID: " + pk.getKeyID());
                }
            }
            byte myEncoded[] = pgpPubCollection.getEncoded();
            try (FileOutputStream fos = new FileOutputStream(PUBLIC_KEY_RING_COLLECTION_FILE_PATH)) {
                fos.write(myEncoded);
            }


        } catch (Exception e) {
            e.printStackTrace();
            return;
        }
    }

    private void removeSecretKey(long keyId) {
        try (FileInputStream keyInputStream = new FileInputStream(SECRET_KEY_RING_COLLECTION_FILE_PATH)) {
            PGPSecretKeyRingCollection pgpSecretKeyRingCollection = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(keyInputStream), new JcaKeyFingerprintCalculator());
            PGPSecretKeyRing keyRing = pgpSecretKeyRingCollection.getSecretKeyRing(keyId);
            System.out.println("BEFORE: " + pgpSecretKeyRingCollection.size());
            if (checkIfSecretKeyRingWithIdExists(keyId, pgpSecretKeyRingCollection)) {
                pgpSecretKeyRingCollection = PGPSecretKeyRingCollection.removeSecretKeyRing(pgpSecretKeyRingCollection, keyRing);
            }
            System.out.println("AFTER: " + pgpSecretKeyRingCollection.size());
            if (pgpSecretKeyRingCollection.iterator().hasNext()) {
                for (PGPSecretKey pk : pgpSecretKeyRingCollection.iterator().next()) {
                    System.out.println("ID: " + pk.getKeyID());
                }
            }
            byte myEncoded[] = pgpSecretKeyRingCollection.getEncoded();
            try (FileOutputStream fos = new FileOutputStream(SECRET_KEY_RING_COLLECTION_FILE_PATH)) {
                fos.write(myEncoded);
            }


        } catch (Exception e) {
            e.printStackTrace();
            return;
        }
    }

    public List<PGPSecretKey> getSecretKeyRingsFromFile() {
//        System.out.println("getSecretKeyRingsFromFile()");
        ArrayList<PGPSecretKey> pgpSecretKeyList = new ArrayList<>();
        try (FileInputStream keyInputStream = new FileInputStream(SECRET_KEY_RING_COLLECTION_FILE_PATH)) {
            PGPSecretKeyRingCollection pgpSecCollection = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(keyInputStream), new JcaKeyFingerprintCalculator()
            );
            System.out.println("collection size" + pgpSecCollection.size());
            Iterator keyRingIter = pgpSecCollection.getKeyRings();
            while (keyRingIter.hasNext()) {
                PGPSecretKeyRing keyRing = (PGPSecretKeyRing) keyRingIter.next();
                Iterator keyIter = keyRing.getSecretKeys();
                while (keyIter.hasNext()) {
                    PGPSecretKey key = (PGPSecretKey) keyIter.next();
                    pgpSecretKeyList.add(key);
//                    System.out.println(key.getKeyID());
                }
            }
//            System.out.println(pgpSecretKeyList.size());
            return pgpSecretKeyList;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        }
        return null;
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

    public PGPPublicKey readPublicKey(String fileName) throws IOException, PGPException {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
        PGPPublicKey pubKey = readPublicKey(keyIn);
        keyIn.close();
        return pubKey;
    }

    private PGPPublicKey readPublicKey(InputStream input) throws IOException, PGPException {
        PGPPublicKeyRing pgpPub = new PGPPublicKeyRing(
                PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());
        try (FileInputStream keyInputStream = new FileInputStream(PUBLIC_KEY_RING_COLLECTION_FILE_PATH)) {
            PGPPublicKeyRingCollection pgpPubCollection = new PGPPublicKeyRingCollection(
                    PGPUtil.getDecoderStream(keyInputStream), new JcaKeyFingerprintCalculator());
            pgpPubCollection = PGPPublicKeyRingCollection.addPublicKeyRing(pgpPubCollection, pgpPub);
            savePublicKeyRingCollectionToFile(pgpPubCollection);
            Iterator keyRingIter = pgpPubCollection.getKeyRings();
            while (keyRingIter.hasNext()) {
                PGPPublicKeyRing keyRing = (PGPPublicKeyRing) keyRingIter.next();


                Iterator keyIter = keyRing.getPublicKeys();
                while (keyIter.hasNext()) {
                    PGPPublicKey key = (PGPPublicKey) keyIter.next();
                    if (key.isEncryptionKey()) {
                        return key;
                    }
                }
            }
        }

        //
        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //


        return null;
    }

    public PGPSecretKey readSecretKey(String fileName) throws IOException, PGPException {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
        PGPSecretKey secKey = readSecretKey(keyIn);
        keyIn.close();
        return secKey;
    }

    private PGPSecretKey readSecretKey(InputStream input) throws IOException, PGPException {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());

        //
        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //

        Iterator keyRingIter = pgpSec.getKeyRings();
//        pgpSec = PGPSecretKeyRingCollection.addSecretKeyRing(pgpSec,keyRingIter.next());
        while (keyRingIter.hasNext()) {
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing) keyRingIter.next();
            saveSecretKeyRing(keyRing);
            Iterator keyIter = keyRing.getSecretKeys();
            while (keyIter.hasNext()) {
                PGPSecretKey key = (PGPSecretKey) keyIter.next();
                System.out.println("READ INSIDE SECRET");
                System.out.println("USERS: " + key.getUserIDs().next() + "KEYID" + key.getKeyID());
                if (key.isSigningKey()) {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Can't find signing key in key ring.");
    }

    public void exportPublicKeyRing(String keyRingIdHexa, String filePath) throws IOException, PGPException {
        try (FileInputStream keyInputStream = new FileInputStream(PUBLIC_KEY_RING_COLLECTION_FILE_PATH)) {
            PGPPublicKeyRingCollection pgpPubCollection = new PGPPublicKeyRingCollection(
                    PGPUtil.getDecoderStream(keyInputStream), new JcaKeyFingerprintCalculator());

            long keyId = Utils.getInstance().hexStringToLongID(keyRingIdHexa);
            PGPPublicKeyRing keyRing = pgpPubCollection.getPublicKeyRing(keyId);

            byte myEncoded[] = keyRing.getEncoded();
            try (FileOutputStream fos = new FileOutputStream(filePath)) {
                fos.write(myEncoded);
            }
        }
    }

    public void exportSecretKeyRing(String keyRingIdHexa, String filePath) throws IOException, PGPException {
        try (FileInputStream keyInputStream = new FileInputStream(SECRET_KEY_RING_COLLECTION_FILE_PATH)) {
            PGPSecretKeyRingCollection pgpSecCollection = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(keyInputStream), new JcaKeyFingerprintCalculator());

            long keyId = Utils.getInstance().hexStringToLongID(keyRingIdHexa);
            PGPSecretKeyRing keyRing = pgpSecCollection.getSecretKeyRing(keyId);
            byte myEncoded[] = keyRing.getEncoded();
            try (FileOutputStream fos = new FileOutputStream(filePath)) {
                fos.write(myEncoded);
            }
        }
    }

    private void savePublicKeyRingCollectionToFile(PGPPublicKeyRingCollection prc) throws IOException {
        byte myEncoded[] = prc.getEncoded();
        try (FileOutputStream fos = new FileOutputStream(PUBLIC_KEY_RING_COLLECTION_FILE_PATH)) {
            fos.write(myEncoded);
            return;
        }

    }

    private void saveSecretKeyRingCollectionToFile(PGPSecretKeyRingCollection src) throws IOException {
        byte myEncoded[] = src.getEncoded();
        try (FileOutputStream fos = new FileOutputStream(SECRET_KEY_RING_COLLECTION_FILE_PATH)) {
            fos.write(myEncoded);
        }
    }

    private boolean checkIfPublicKeyRingWithIdExists(long keyRingId, PGPPublicKeyRingCollection pkrc) throws PGPException {
        if (pkrc.getPublicKeyRing(keyRingId) == null) {
            return false;
        }
        return true;
    }

    private boolean checkIfSecretKeyRingWithIdExists(long keyRingId, PGPSecretKeyRingCollection skrc) throws PGPException {
        if (skrc.getSecretKeyRing(keyRingId) == null) {
            return false;
        }
        return true;
    }

    private PGPSecretKey getSecretKey(String userInfo) throws IOException {
        List<PGPSecretKey> secretKeyRing = KeyRingHelper.getInstance().getSecretKeyRingsFromFile();
        for (Iterator<PGPSecretKey> it = secretKeyRing.iterator(); it.hasNext(); ) {
            PGPSecretKey sk = it.next();
            if (sk.getUserIDs().hasNext())
                if (sk.getUserIDs().next().equals(userInfo)) {
                    System.out.println("SIGN AS: " + sk.getUserIDs().next() + " ENCRYPT FOR: " + userInfo);
                    System.out.println("SECRET KEY:" + sk.getKeyID());
                    return sk;
                }
        }
        return null;
    }

    public PGPPrivateKey getPrivateKey(String userInfo, String passPhrase) throws IOException, PGPException {

        PGPSecretKey secret = getSecretKey(userInfo);
        PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(passPhrase.toCharArray());
        return secret.extractPrivateKey(decryptor);

    }

    public PGPPublicKey getPublicKey(long keyID) throws IOException, PGPException {
        try (FileInputStream keyInputStream = new FileInputStream(PUBLIC_KEY_RING_COLLECTION_FILE_PATH)) {
            PGPPublicKeyRingCollection pgpPubCollection = new PGPPublicKeyRingCollection(
                    PGPUtil.getDecoderStream(keyInputStream), new JcaKeyFingerprintCalculator());
            return pgpPubCollection.getPublicKey(keyID);
        }

    }
}
