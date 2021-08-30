import models.User;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.*;
import org.bouncycastle.jcajce.provider.symmetric.IDEA;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.openpgp.operator.bc.BcPBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;
import utils.KeyRingHelper;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

/**
 * A class used to generate a PGPMessage
 */
public class PGPMessage {
    private String message;
    long from;
    List<Long> sendTo;
    private boolean authentication, privacy, compression, conversion, des, idea;
    private String chipertext;
    User userSendTo;
    String passPhrase;
    PGPPrivateKey privateKey;
    int symmetricKeyAlgorithm;

    public PGPMessage(String message,
                      long from,
                      List<Long> sendTo,
                      boolean authentication,
                      boolean privacy,
                      boolean compression,
                      boolean conversion,
                      boolean des,
                      int symetricKeyAlgorithm,
                      boolean idea,
                      String passPhrase) {
        this.message = message;
        this.from = from;
        this.sendTo = sendTo;
        this.authentication = authentication;
        this.privacy = privacy;
        this.compression = compression;
        this.conversion = conversion;
        this.des = des;
        this.idea = idea;
        this.passPhrase = passPhrase;
        this.symmetricKeyAlgorithm = symetricKeyAlgorithm;

        userSendTo = User.getInfoFromUser(sendTo.toString());

    }

    /**
     * A helper function used to get the secret key
     *
     * @return
     */
    public PGPPrivateKey getPrivateKey() {
        try {
            return privateKey = KeyRingHelper.getInstance().getPrivateKey(from, passPhrase);
        } catch (IOException | PGPException e) {
//            e.printStackTrace();
            return null;
        }
    }

    /**
     * Function used to verify the passphrase entered for the secret key
     *
     * @return
     */
    public boolean verifyPassPhrase() {
        PGPPrivateKey pk = getPrivateKey();
        if (pk == null) return false;
        else {
            System.out.println("VERIFIED SECRET KEY:" + pk.getKeyID());
            return true;
        }
    }

    public String getChipertext() {
        return chipertext;
    }

    public void setChipertext(String chipertext) {
        this.chipertext = chipertext;
    }

    /**
     * A function used to compress a message
     *
     * @param message
     * @return
     * @throws IOException
     */
    public byte[] compress(String message) throws IOException {
        byte[] data = message.getBytes();
        PGPCompressedDataGenerator compressGen = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        OutputStream compressOut = compressGen.open(bos);
        OutputStream os =
                new PGPLiteralDataGenerator().open(compressOut, PGPLiteralData.BINARY, "", data.length, new Date());
        os.write(data);
        os.close();
        compressGen.close();
        return bos.toByteArray();
    }

    public void authentication(String from, String sendTo, String alg) {

    }

    public void compression() {

    }

    public void conversion() {

    }


    /**
     * A function used to generate and save a message into a file
     *
     * @throws IOException
     * @throws PGPException
     */
    public void sendMessage() throws IOException, PGPException {
        if (authentication) {
            PGPSecretKey secretKey = KeyRingHelper.getInstance().getSecretKey(from);
            String messageSignature = signMessageByteArray(message, secretKey, from, passPhrase);

            chipertext = messageSignature;
        }
        if (privacy) {

            byte[] ch = encryptMessageUsingSessionKey(message, KeyRingHelper.getInstance().getPublicKeysBasedOnKeys(sendTo), symmetricKeyAlgorithm);
//             createEncryptedData(publicKey,message.getBytes());
//            chipertext = msg;
//            String encryptedMessage = null;
//            encryptedMessage = encryptByteArray(message.getBytes(), publicKey);

        }
    }

    /**
     * Function used to sign a message with a secret key
     *
     * @param message
     * @param secretKey
     * @param from
     * @param passPhrase
     * @return
     * @throws IOException
     * @throws PGPException
     */
    private static String signMessageByteArray(String message,
                                               PGPSecretKey secretKey,
                                               long from,
                                               String passPhrase) throws IOException, PGPException {

        byte[] messageCharArray = message.getBytes();
        PGPPrivateKey privateKey = KeyRingHelper.getInstance().getPrivateKey(from, passPhrase);
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1).setProvider("BC"));
        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);

        ByteArrayOutputStream encOut = new ByteArrayOutputStream();
        OutputStream out = encOut;
        out = new ArmoredOutputStream(out);

        Iterator it = secretKey.getPublicKey().getUserIDs();
        if (it.hasNext()) {
            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
            spGen.setSignerUserID(false, (String) it.next());
            signatureGenerator.setHashedSubpackets(spGen.generate());
        }
        PGPCompressedDataGenerator cGen = new PGPCompressedDataGenerator(PGPCompressedData.ZLIB);
        BCPGOutputStream bOut = new BCPGOutputStream(cGen.open(out));
        signatureGenerator.generateOnePassVersion(false).encode(bOut);

        PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
        OutputStream lOut = lGen.open(bOut, PGPLiteralData.BINARY,
                PGPLiteralData.CONSOLE, messageCharArray.length, new Date());
        for (byte c : messageCharArray) {
            lOut.write(c);
            signatureGenerator.update(c);
        }

        lGen.close();
        signatureGenerator.generate().encode(bOut);
        cGen.close();
        out.close();

        return encOut.toString();
    }

    /**
     * Function used to verify an OpenPGP file
     *
     * @param in
     * @return
     * @throws Exception
     */
    public static boolean verifyFile(
            InputStream in)
            throws Exception {
        in = PGPUtil.getDecoderStream(in);

        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(in);

        PGPCompressedData c1 = (PGPCompressedData) pgpFact.nextObject();

        pgpFact = new JcaPGPObjectFactory(c1.getDataStream());

        PGPOnePassSignatureList p1 = (PGPOnePassSignatureList) pgpFact.nextObject();

        PGPOnePassSignature ops = p1.get(0);

        PGPLiteralData p2 = (PGPLiteralData) pgpFact.nextObject();

        InputStream dIn = p2.getInputStream();
        int ch;
        KeyRingHelper.getInstance().getPublicKey(ops.getKeyID());

        PGPPublicKey key = KeyRingHelper.getInstance().getPublicKey(ops.getKeyID());
        if (key == null) {
            System.out.println("signature verification failed.");
            return false;
        }
        FileOutputStream out = new FileOutputStream(p2.getFileName());

        ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);

        while ((ch = dIn.read()) >= 0) {
            ops.update((byte) ch);
            out.write(ch);
        }

        out.close();

        PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();

        if (ops.verify(p3.get(0))) {
            System.out.println("signature verified.");
            return true;
        } else {
            System.out.println("signature verification failed.");
            return false;
        }
    }

    /**
     * Function used to encrypt a message using a session key generated in it
     *
     * @param message
     * @param pgpPublicKeyList
     * @param symetricAlgoritmCode
     * @return
     */
    public byte[] encryptMessageUsingSessionKey(String message, List<PGPPublicKey> pgpPublicKeyList, int symetricAlgoritmCode) {
        System.out.println("usao");
        try {

            OutputStream out = new ArmoredOutputStream(new BufferedOutputStream(new FileOutputStream("test.txt")));
            byte[] bytes = compress(message);

            PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder(symetricAlgoritmCode).setWithIntegrityPacket(true).setSecureRandom(new SecureRandom()).setProvider("BC"));
            pgpPublicKeyList.forEach(pgpPublicKey -> {
                encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pgpPublicKey).setProvider("BC"));
            });
            OutputStream cOut = encGen.open(out, bytes.length);

            cOut.write(bytes);
            cOut.close();
            out.close();

        } catch (IOException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void decryptFile(
            InputStream in,
            InputStream keyIn,
            char[]      passwd,
            String      defaultFileName)
            throws IOException, NoSuchProviderException
    {
        in = PGPUtil.getDecoderStream(in);
        try
        {
            JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
            PGPEncryptedDataList    enc;
            Object o = pgpF.nextObject();
            //
            // the first object might be a PGP marker packet.
            //
            if (o instanceof PGPEncryptedDataList)
            {
                enc = (PGPEncryptedDataList)o;
            }
            else
            {
                enc = (PGPEncryptedDataList)pgpF.nextObject();
            }


            Iterator                    it = enc.getEncryptedDataObjects();
            PGPPrivateKey               sKey = null;
            PGPPublicKeyEncryptedData   pbe = null;
            PGPSecretKeyRingCollection  pgpSec = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());

            while (sKey == null && it.hasNext()) {
                pbe = (PGPPublicKeyEncryptedData)it.next();
                sKey = findSecretKey(pgpSec, pbe.getKeyID(), passwd);
            }

            if (sKey == null) {
                throw new IllegalArgumentException("secret key for message not found.");
            }

            InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));
            JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);
            Object  message = plainFact.nextObject();

            if (message instanceof PGPCompressedData) {
                PGPCompressedData   cData = (PGPCompressedData)message;
                JcaPGPObjectFactory    pgpFact = new JcaPGPObjectFactory(cData.getDataStream());
                message = pgpFact.nextObject();
            }

            if (message instanceof PGPLiteralData) {
                PGPLiteralData ld = (PGPLiteralData)message;
                String outFileName = ld.getFileName();
                if (outFileName.length() == 0) {
                    outFileName = defaultFileName;
                }

                InputStream unc = ld.getInputStream();
                OutputStream fOut = new FileOutputStream(outFileName);
                Streams.pipeAll(unc, fOut);
                fOut.close();
            }
            else if (message instanceof PGPOnePassSignatureList) {
                throw new PGPException("encrypted message contains a signed message - not literal data.");
            }
            else {
                throw new PGPException("message is not a simple encrypted file - type unknown.");
            }

            if (pbe.isIntegrityProtected()) {
                if (!pbe.verify()) {
                    System.err.println("message failed integrity check");
                }
                else {
                    System.err.println("message integrity check passed");
                }
            }
            else  {
                System.err.println("no message integrity check");
            }
        }
        catch (PGPException e) {
            System.err.println(e);
            if (e.getUnderlyingException() != null) {
                e.getUnderlyingException().printStackTrace();
            }
        }
    }

    /**
     * Search a secret key ring collection for a secret key corresponding to keyID if it
     * exists.
     *
     * @param pgpSec a secret key ring collection.
     * @param keyID keyID we want.
     * @param pass passphrase to decrypt secret key with.
     * @return the private key.
     * @throws PGPException
     * @throws NoSuchProviderException
     */
    static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass)
            throws PGPException, NoSuchProviderException {

        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);
        if (pgpSecKey == null) {
            return null;
        }

        return pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
    }

}
