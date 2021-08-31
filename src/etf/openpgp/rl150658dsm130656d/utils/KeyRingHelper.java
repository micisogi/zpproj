package etf.openpgp.rl150658dsm130656d.utils;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import javax.swing.*;
import java.io.*;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;


/**
 * A Util singleton class used to manipulate KeyRings.
 */
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
            fosPublic.flush();
            fosPublic.close();
        }
        if (!existsSecretKeyCollection) {
            FileOutputStream fosSecret = new FileOutputStream(SECRET_KEY_RING_COLLECTION_FILE_PATH);
            fosSecret.flush();
            fosSecret.close();
        }
    }

    /**
     * Function to return an object of the singleton
     *
     * @return
     * @throws IOException
     */
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

    /**
     * A helper function to save a secret key ring to the secret key ring collection file
     *
     * @param pgpSecretKeyRing
     * @return
     */
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


    /**
     * A helper function to save a secret key ring to the public key ring collection file
     *
     * @param pgpPublicKeyRing
     * @return
     */
    public Iterator<PGPPublicKeyRing> savePublicKeyRing(PGPPublicKeyRing pgpPublicKeyRing) {
        try (FileInputStream keyInputStream = new FileInputStream(PUBLIC_KEY_RING_COLLECTION_FILE_PATH)) {
            PGPPublicKeyRingCollection pgpPubCollection = new PGPPublicKeyRingCollection(
                    PGPUtil.getDecoderStream(keyInputStream), new JcaKeyFingerprintCalculator());
            pgpPubCollection = PGPPublicKeyRingCollection.addPublicKeyRing(pgpPubCollection, pgpPublicKeyRing);
            for (PGPPublicKey pk : pgpPubCollection.iterator().next()) {
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

    /**
     * A helper function used to delete a Key Ring
     *
     * @param keyRingIdHexa
     */
    public void deleteKeyRing(String keyRingIdHexa) {
        try (FileInputStream keyInputStream = new FileInputStream(PUBLIC_KEY_RING_COLLECTION_FILE_PATH)) {
            PGPPublicKeyRingCollection pgpPubCollection = new PGPPublicKeyRingCollection(
                    PGPUtil.getDecoderStream(keyInputStream), new JcaKeyFingerprintCalculator());
            long keyId = Utils.getInstance().hexStringToLongID(keyRingIdHexa);
            PGPPublicKeyRing keyRing = pgpPubCollection.getPublicKeyRing(keyId);
            if (checkIfPublicKeyRingWithIdExists(keyId, pgpPubCollection)) {
                pgpPubCollection = PGPPublicKeyRingCollection.removePublicKeyRing(pgpPubCollection, keyRing);
            }
            removeSecretKey(keyId);
            if (pgpPubCollection.iterator().hasNext()) {
                for (PGPPublicKey pk : pgpPubCollection.iterator().next()) {
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

    /**
     * A helper function used to remove the secret key from the secretKeyRingCollection
     *
     * @param keyId
     */
    private void removeSecretKey(long keyId) {
        try (FileInputStream keyInputStream = new FileInputStream(SECRET_KEY_RING_COLLECTION_FILE_PATH)) {
            PGPSecretKeyRingCollection pgpSecretKeyRingCollection = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(keyInputStream), new JcaKeyFingerprintCalculator());
            PGPSecretKeyRing keyRing = pgpSecretKeyRingCollection.getSecretKeyRing(keyId);
            if (checkIfSecretKeyRingWithIdExists(keyId, pgpSecretKeyRingCollection)) {
                pgpSecretKeyRingCollection = PGPSecretKeyRingCollection.removeSecretKeyRing(pgpSecretKeyRingCollection, keyRing);
            }
            if (pgpSecretKeyRingCollection.iterator().hasNext()) {
                for (PGPSecretKey pk : pgpSecretKeyRingCollection.iterator().next()) {
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

    /**
     * A helper function used to return a list of secret keys stored in the secret key ring collection file
     *
     * @return
     */
    public List<PGPSecretKey> getSecretKeyRingsFromFile() {
        ArrayList<PGPSecretKey> pgpSecretKeyList = new ArrayList<>();
        try (FileInputStream keyInputStream = new FileInputStream(SECRET_KEY_RING_COLLECTION_FILE_PATH)) {
            PGPSecretKeyRingCollection pgpSecCollection = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(keyInputStream), new JcaKeyFingerprintCalculator()
            );
            Iterator keyRingIter = pgpSecCollection.getKeyRings();
            while (keyRingIter.hasNext()) {
                PGPSecretKeyRing keyRing = (PGPSecretKeyRing) keyRingIter.next();
                Iterator keyIter = keyRing.getSecretKeys();
                while (keyIter.hasNext()) {
                    PGPSecretKey key = (PGPSecretKey) keyIter.next();
                    pgpSecretKeyList.add(key);
                }
            }
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

    /**
     * A helper function used to return a list of public keys stored in the public key ring collection file
     *
     * @return
     */
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

    /**
     * A helper function used to read a public .asc file
     *
     * @param fileName
     * @return
     * @throws IOException
     * @throws PGPException
     */
    public PGPPublicKey readPublicKey(String fileName) throws IOException, PGPException {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
        PGPPublicKey pubKey = readPublicKey(keyIn);
        keyIn.close();
        return pubKey;
    }

    /**
     * A helper function to insert a public key into the public key ring collection file
     *
     * @param input
     * @return
     * @throws IOException
     * @throws PGPException
     */
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
        return null;
    }

    /**
     * A helper function used to read a secret .asc file
     *
     * @param fileName
     * @return
     * @throws IOException
     * @throws PGPException
     */
    public PGPSecretKey readSecretKey(String fileName) throws IOException, PGPException {
        System.out.println("BOBAN SAULIC");
        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
        PGPSecretKey secKey = readSecretKey(keyIn);
        keyIn.close();
        return secKey;
    }

    /**
     * A helper function to insert a secret key into the secret key ring collection file
     *
     * @param input
     * @return
     * @throws IOException
     * @throws PGPException
     */
    private PGPSecretKey readSecretKey(InputStream input) throws IOException, PGPException {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());
        Iterator keyRingIter = pgpSec.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing) keyRingIter.next();
            saveSecretKeyRing(keyRing);
            Iterator keyIter = keyRing.getSecretKeys();
            while (keyIter.hasNext()) {
                PGPSecretKey key = (PGPSecretKey) keyIter.next();
                if (key.isSigningKey()) {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Can't find signing key in key ring.");
    }

    /**
     * A helper function used to export the public key ring into a .asc file
     *
     * @param keyRingIdHexa
     * @param filePath
     * @throws IOException
     * @throws PGPException
     */
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

    /**
     * A helper function used to export the secret key ring into a .asc file
     *
     * @param keyRingIdHexa
     * @param filePath
     * @throws IOException
     * @throws PGPException
     */
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

    /**
     * A helper function used to save a public key ring collection into a file
     *
     * @param prc
     * @throws IOException
     */
    private void savePublicKeyRingCollectionToFile(PGPPublicKeyRingCollection prc) throws IOException {
        byte myEncoded[] = prc.getEncoded();
        try (FileOutputStream fos = new FileOutputStream(PUBLIC_KEY_RING_COLLECTION_FILE_PATH)) {
            fos.write(myEncoded);
            return;
        }

    }

    /**
     * A helper function used to save a secret key ring collection into a file
     *
     * @param src
     * @throws IOException
     */
    private void saveSecretKeyRingCollectionToFile(PGPSecretKeyRingCollection src) throws IOException {
        byte myEncoded[] = src.getEncoded();
        try (FileOutputStream fos = new FileOutputStream(SECRET_KEY_RING_COLLECTION_FILE_PATH)) {
            fos.write(myEncoded);
        }
    }

    /**
     * A helper function used to check if a public key ring with given Id exists
     *
     * @param keyRingId
     * @param pkrc
     * @return
     * @throws PGPException
     */
    private boolean checkIfPublicKeyRingWithIdExists(long keyRingId, PGPPublicKeyRingCollection pkrc) throws PGPException {
        if (pkrc.getPublicKeyRing(keyRingId) == null) {
            return false;
        }
        return true;
    }

    /**
     * A helper function used to check if a secret key ring with given Id exists
     *
     * @param keyRingId
     * @param skrc
     * @return
     * @throws PGPException
     */
    private boolean checkIfSecretKeyRingWithIdExists(long keyRingId, PGPSecretKeyRingCollection skrc) throws PGPException {
        if (skrc.getSecretKeyRing(keyRingId) == null) {
            return false;
        }
        return true;
    }

    /**
     * A helper function used to return a secret key from the secret key ring collection file
     *
     * @param userId
     * @return
     */
    public PGPSecretKey getSecretKey(long userId) {
        List<PGPSecretKey> secretKeyRing = getSecretKeyRingsFromFile();
        for (Iterator<PGPSecretKey> it = secretKeyRing.iterator(); it.hasNext(); ) {
            PGPSecretKey sk = it.next();
            if (sk.getKeyID() == userId) {
                return sk;
            }
        }
        return null;
    }

    /**
     * A helper function used to check if password for the secret key matches
     *
     * @param userId
     * @param passPhrase
     * @return
     * @throws IOException
     * @throws PGPException
     */
    public PGPPrivateKey getPrivateKey(long userId, String passPhrase) throws IOException, PGPException {

        PGPSecretKey secret = getSecretKey(userId);
        PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(passPhrase.toCharArray());
        return secret.extractPrivateKey(decryptor);

    }

    /**
     * A helper function used to check if password for the secret key matches
     *
     * @param userId
     * @param ch
     * @return
     */
    public PGPPrivateKey getPrivateKey(long userId, char[] ch) {

        PGPSecretKey secret = getSecretKey(userId);
        PGPPrivateKey sk;
        if (secret == null) {
            return null;
        }
        try {
            sk = secret.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(ch));
            return sk;
        } catch (PGPException e) {
            String passPhrase = JOptionPane.showInputDialog("Enter a password for the private key");
            return getPrivateKey(userId, passPhrase.toCharArray());
        }
    }

    /**
     * A helper function used to return a public key from the public key ring collection file
     *
     * @param keyID
     * @return
     * @throws IOException
     * @throws PGPException
     */
    public PGPPublicKey getPublicKey(long keyID) throws IOException, PGPException {
        try (FileInputStream keyInputStream = new FileInputStream(PUBLIC_KEY_RING_COLLECTION_FILE_PATH)) {
            PGPPublicKeyRingCollection pgpPubCollection = new PGPPublicKeyRingCollection(
                    PGPUtil.getDecoderStream(keyInputStream), new JcaKeyFingerprintCalculator());
            return pgpPubCollection.getPublicKey(keyID);
        }
    }

    /**
     * A helper function used to return a public key from the keyID
     *
     * @param keyIDs
     * @return
     * @throws IOException
     * @throws PGPException
     */
    public List<PGPPublicKey> getPublicKeysBasedOnKeys(List<Long> keyIDs) throws IOException, PGPException {

        ArrayList<PGPPublicKey> returnList = new ArrayList<>();
        try (FileInputStream keyInputStream = new FileInputStream(PUBLIC_KEY_RING_COLLECTION_FILE_PATH)) {
            PGPPublicKeyRingCollection pgpPubCollection = new PGPPublicKeyRingCollection(
                    PGPUtil.getDecoderStream(keyInputStream), new JcaKeyFingerprintCalculator());
            keyIDs.forEach(keyID -> {
                try {
                    PGPPublicKeyRing keyRing = pgpPubCollection.getPublicKeyRing(keyID);
                    Iterator keyRingIter = keyRing.getPublicKeys();
                    while (keyRingIter.hasNext()) {
                        PGPPublicKey key = (PGPPublicKey) keyRingIter.next();
                        if (key.isEncryptionKey()) {
                            returnList.add(key);
                        }
                    }

                } catch (PGPException e) {
                    e.printStackTrace();
                }
            });
            return returnList;
        }
    }

    /**
     * A function used to verufy password before delition
     *
     * @param keyId
     * @param type
     * @return
     * @throws PGPException
     * @throws IOException
     */
    public boolean verifyPassPhrase(long keyId, String type) throws PGPException, IOException {
        if (type.equals("PUBLIC")) return true;
        else {
            String passPhrase = JOptionPane.showInputDialog("Enter a password for the private key");
            PGPPrivateKey privKey = KeyRingHelper.getInstance().getPrivateKey(keyId, passPhrase.toCharArray());

            if (privKey == null) return true;
            else {
            System.out.println("VERIFIED SECRET KEY:" + privKey.getKeyID());
                return true;
            }
        }
    }

}
