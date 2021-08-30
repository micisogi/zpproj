import models.User;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.*;
import org.bouncycastle.jcajce.provider.symmetric.IDEA;
import org.bouncycastle.jcajce.provider.symmetric.XSalsa20;
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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
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
    User userSendTo;
    String passPhrase;
    PGPPrivateKey privateKey;
    int symmetricKeyAlgorithm;
    String filepath;

    public String getChipherText() {
        return chipherText;
    }

    String chipherText;


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

    public String getFilepath() {
        return filepath;
    }

    public void setFilepath(String filepath) {
        this.filepath = filepath;
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

    public void authentication() throws IOException, PGPException {
        PGPSecretKey secretKey = KeyRingHelper.getInstance().getSecretKey(from);
        String messageSignature = signMessageByteArray(message, secretKey, passPhrase);
        Path path = Paths.get("test");
        Files.write(path, Base64.getEncoder().encode(Strings.toByteArray(messageSignature)));
//        chipherText = ;


    }

    public void conversion() {

    }

    public void privacy() throws IOException, PGPException {
        encryptMessageUsingSessionKey(message, KeyRingHelper.getInstance().getPublicKeysBasedOnKeys(sendTo), symmetricKeyAlgorithm, filepath);
        return;
    }


    /**
     * A function used to generate and save a message into a file
     *
     * @throws IOException
     * @throws PGPException
     */
    public void sendMessage() throws IOException, PGPException {
        if (authentication) {
            authentication();
        }
        if (privacy) {
            privacy();

        }
    }

    /**
     * Function used to sign a message with a secret key
     *
     * @param message
     * @param secretKey
     * @param passPhrase
     * @return
     * @throws IOException
     * @throws PGPException
     */
    private static String signMessageByteArray(String message,
                                               PGPSecretKey secretKey,
                                               String passPhrase) throws IOException, PGPException {

        byte[] messageCharArray = message.getBytes();
        PGPPrivateKey privateKey = secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passPhrase.toCharArray()));
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1).setProvider("BC"));
        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);

        ByteArrayOutputStream encOut = new ByteArrayOutputStream();
        OutputStream out = encOut;
        out = new ArmoredOutputStream(out);

        Iterator it = secretKey.getPublicKey().getUserIDs();
        if (it.hasNext()) {
            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
            spGen.addSignerUserID(false, (String) it.next());
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
    public byte[] encryptMessageUsingSessionKey(String message, List<PGPPublicKey> pgpPublicKeyList, int symetricAlgoritmCode, String filepath) {
        try {
            ByteArrayOutputStream encOut = new ByteArrayOutputStream();

            OutputStream out = encOut;
            out = new ArmoredOutputStream(new BufferedOutputStream(new FileOutputStream(filepath)));
            byte[] bytes = compress(message);

            PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder(symetricAlgoritmCode).setWithIntegrityPacket(true).setSecureRandom(new SecureRandom()).setProvider("BC"));
            pgpPublicKeyList.forEach(pgpPublicKey -> {
                encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pgpPublicKey).setProvider("BC"));
            });
            ByteArrayOutputStream cOut = (ByteArrayOutputStream) encGen.open(out, bytes.length);

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

    private static String encodeFileToBase64(File file) {
        try {
            byte[] fileContent = Files.readAllBytes(file.toPath());
            return Base64.getEncoder().encodeToString(fileContent);
        } catch (IOException e) {
            throw new IllegalStateException("could not read file " + file, e);
        }
    }
}
