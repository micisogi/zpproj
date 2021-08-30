import models.User;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;
import utils.KeyRingHelper;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
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

    public void authentication() throws IOException, PGPException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException {
        System.out.println("Usao sam autentikacija");
        PGPSecretKey secretKey = KeyRingHelper.getInstance().getSecretKey(from);
        message = signMessageByteArray(message, secretKey, passPhrase);
        writeToFile(filepath, message);
        Path path = Paths.get("test");
//        Files.write(path, Base64.getEncoder().encode(Strings.toByteArray(message)));
    }

    public void authenticationAndPrivacy() throws IOException, PGPException {
        PGPSecretKey secretKey = KeyRingHelper.getInstance().getSecretKey(from);
        String messageSignature = signMessageByteArray(message, secretKey, passPhrase);
        encryptMessageUsingSessionKey(messageSignature, KeyRingHelper.getInstance().getPublicKeysBasedOnKeys(sendTo), symmetricKeyAlgorithm, filepath);
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
    public void sendMessage() throws IOException, PGPException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException {
        if (authentication && !privacy) {
            authentication();
        }
        if (privacy && !authentication) {
            privacy();
        }
        if (authentication && privacy) {
            authenticationAndPrivacy();
        }
        if(compression){
            String str = readFromFileIntoString(filepath);
            byte[] bytes = compress(str);
//            writeToFile();
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
        System.out.println("usaoi u auth");
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
        BCPGOutputStream bOut = new BCPGOutputStream(out);
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
        System.out.println("Usao sam ekripcija");
            OutputStream out = new ArmoredOutputStream(new BufferedOutputStream(new FileOutputStream(filepath)));
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

    private static String encodeFileToBase64(File file) {
        try {
            byte[] fileContent = Files.readAllBytes(file.toPath());
            return Base64.getEncoder().encodeToString(fileContent);
        } catch (IOException e) {
            throw new IllegalStateException("could not read file " + file, e);
        }
    }

    private static void writeToFile(String filepath, String message) {
        try {
            FileWriter fw = new FileWriter(filepath);
            fw.write(message);
            fw.close();
        } catch (Exception e) {
            System.out.println(e);
        }
//        System.out.println("Success...");
    }

    private static String readFromFileIntoString(String filePath) {
        StringBuilder contentBuilder = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {

            String sCurrentLine;
            while ((sCurrentLine = br.readLine()) != null) {
                contentBuilder.append(sCurrentLine).append("\n");
            }
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        return contentBuilder.toString();
    }
//    public String encryptByteArray(byte[] clearData, List<PGPPublicKey> pgpPublicKeyList)
//            throws IOException, PGPException, NoSuchProviderException {
//
//        ByteArrayOutputStream encOut = new ByteArrayOutputStream();
//
//        OutputStream out = encOut;
//        out = new ArmoredOutputStream(out);
//
//        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
//
//        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(
//                PGPCompressedDataGenerator.ZIP);
//        OutputStream cos = comData.open(bOut);
//
//        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
//
//        OutputStream pOut = lData.open(cos, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, clearData.length, new Date());
//        pOut.write(clearData);
//
//        lData.close();
//        comData.close();
//
//        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(symmetricKeyAlgorithm).setWithIntegrityPacket(true).setSecureRandom(new SecureRandom()).setProvider("BC"));
//        pgpPublicKeyList.forEach(pgpPublicKey -> {
//            encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pgpPublicKey).setProvider("BC"));
//        }););
//
//        cPk.addMethod(encKey);
//
//        byte[] bytes = bOut.toByteArray();
//
//        OutputStream cOut = cPk.open(out, bytes.length);
//
//        cOut.write(bytes); // obtain the actual bytes from the compressed stream
//
//        cOut.close();
//
//        out.close();
//
//        return encOut.toString();
//    }


    public static void decrypt(InputStream in, JPanel mainPanel) throws IOException {
        in = PGPUtil.getDecoderStream(in);
        try {
            JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
            PGPEncryptedDataList enc;
            Object o = pgpF.nextObject();
            //
            // the first object might be a PGP marker packet.
            //
            if (o instanceof PGPEncryptedDataList) {
                enc = (PGPEncryptedDataList) o;
            } else {
                enc = (PGPEncryptedDataList) pgpF.nextObject();
            }
            Iterator it = enc.getEncryptedDataObjects();
            PGPPrivateKey sKey = null;
            PGPPublicKeyEncryptedData pbe = null;

            while (sKey == null && it.hasNext()) {
                pbe = (PGPPublicKeyEncryptedData) it.next();
                char[] myChars = new char[1];
                myChars[0] = '"';
                sKey = KeyRingHelper.getInstance().getPrivateKey(pbe.getKeyID(), myChars);
            }

            InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));
            JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);
            Object message = plainFact.nextObject();
            if (message instanceof PGPCompressedData) {
                PGPCompressedData cData = (PGPCompressedData) message;
                JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(cData.getDataStream());

                message = pgpFact.nextObject();
            }
            String outFileName;
            if (message instanceof PGPLiteralData) {
                PGPLiteralData ld = (PGPLiteralData) message;
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setCurrentDirectory(new File(System.getProperty("user.home")));
                fileChooser.setFileFilter(new FileNameExtensionFilter("*.txt", "txt"));
                int result = fileChooser.showOpenDialog(mainPanel);
                if (result == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = fileChooser.getSelectedFile();
                   outFileName = selectedFile.getAbsolutePath();
                    if (!outFileName.substring(outFileName.lastIndexOf(".") + 1).equals("txt"))
                        outFileName += ".txt";
                } else {
                    outFileName = ld.getFileName();
                    if (outFileName.length() == 0) {
                        outFileName = "defaultImeFajla";
                    }
                }

                InputStream unc = ld.getInputStream();
                OutputStream fOut = new FileOutputStream(outFileName);

                Streams.pipeAll(unc, fOut);

                fOut.close();
            } else if (message instanceof PGPOnePassSignatureList) {
                throw new PGPException("encrypted message contains a signed message - not literal data.");
            } else {
                throw new PGPException("message is not a simple encrypted file - type unknown.");
            }

            if (pbe.isIntegrityProtected()) {
                if (!pbe.verify()) {
                    JOptionPane.showMessageDialog(null, "Message failed integrity check.");
                    System.err.println("");
                } else {
                    JOptionPane.showMessageDialog(null, "Message integrity check passed.");
                }
            } else {
                JOptionPane.showMessageDialog(null, "No message integrity check.");
            }

        } catch (PGPException e) {
            System.err.println(e);
            if (e.getUnderlyingException() != null) {
                e.getUnderlyingException().printStackTrace();
            }
        }
    }
}
