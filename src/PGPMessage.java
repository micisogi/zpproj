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
     * A function used to get a filepath
     *
     * @return
     */
    public String getFilepath() {
        return filepath;
    }

    /**
     * A function used to set a filepath
     *
     * @param filepath
     */
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

    /**
     * A function used to sign and save message into a file
     *
     * @throws IOException
     * @throws PGPException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws NoSuchProviderException
     */
    public void authentication() throws IOException, PGPException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException {
       if(!privacy) {
           System.out.println("Usao sam autentikacija");
           PGPSecretKey secretKey = KeyRingHelper.getInstance().getSecretKey(from);
           message = signMessageByteArray(message, secretKey, passPhrase);
           writeToFile(filepath, message);
       }

    }

    /**
     * A function used to sign, encrypt and save message into a file
     *
     * @throws IOException
     * @throws PGPException
     */
    public void authenticationAndPrivacy() throws IOException, PGPException {
        PGPSecretKey secretKey = KeyRingHelper.getInstance().getSecretKey(from);
        String messageSignature = signMessageByteArray(message, secretKey, passPhrase);
        encryptMessageUsingSessionKey(messageSignature, KeyRingHelper.getInstance().getPublicKeysBasedOnKeys(sendTo), symmetricKeyAlgorithm, filepath);
    }

    public void conversion() throws IOException {
        if(!authentication && !privacy && !compression){
            writeToFile(filepath,message);
        }
        Path path = Paths.get(filepath);
        String msg = readFromFileIntoString(filepath);
        Files.write(path, Base64.getEncoder().encode(Strings.toByteArray(msg)));
    }

    /**
     * A function used to encrypt and save message into a file
     *
     * @throws IOException
     * @throws PGPException
     */
    public void privacy() throws IOException, PGPException {
        if(!authentication) {
            encryptMessageUsingSessionKey(message, KeyRingHelper.getInstance().getPublicKeysBasedOnKeys(sendTo), symmetricKeyAlgorithm, filepath);
            return;
        }
    }

    /**
     * A function used to compress and save into a file
     *
     * @throws IOException
     */
    private void compression() throws IOException {
        if(!privacy && !authentication){
            writeToFile(filepath,message);
        }
        String str = readFromFileIntoString(filepath);
        byte[] bytes = compress(str);
        ByteArrayOutputStream encOut = new ByteArrayOutputStream();
        OutputStream out = encOut;
        out = new ArmoredOutputStream(out);
        out.write(bytes);
        out.close();
    }


    /**
     * A function used to generate and save a message into a file
     *
     * @throws IOException
     * @throws PGPException
     */
    public void sendMessage() throws IOException, PGPException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException {
        if (authentication) {
            authentication();
        }
        if (privacy) {
            privacy();
        }
        if (authentication && privacy) {
            authenticationAndPrivacy();
        }
<<<<<<< HEAD
        if(compression){
=======
        if (compression && !privacy) {
>>>>>>> 925f60ab5c79b086331144b65c89b656315b1a6f
            compression();
        }
        if (conversion) {
            conversion();
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
            InputStream in, JPanel mainPanel)
            throws Exception {

        return false;
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

    /**
     * Function used to write a message into a file
     *
     * @param filepath
     * @param message
     */
    private static void writeToFile(String filepath, String message) {
        try {
            FileWriter fw = new FileWriter(filepath);
            fw.write(message);
            fw.close();
        } catch (Exception e) {
            System.out.println(e);
        }

    }

    /**
     * Function used to read a message from a file
     *
     * @param filePath
     * @return
     */
    private static String readFromFileIntoString(String filePath) {
        StringBuilder contentBuilder = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {

            String sCurrentLine;
            while ((sCurrentLine = br.readLine()) != null) {
                contentBuilder.append(sCurrentLine).append("\n");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return contentBuilder.toString();
    }

    /**
     * Function used to decrypt a message from a file
     *
     * @param in
     * @param mainPanel
     * @throws IOException
     */
    public static void decrypt(InputStream in, JPanel mainPanel) throws IOException {
        System.out.println("USAO U DECRYPT");
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
            if (sKey == null) {
                JOptionPane.showMessageDialog(null, "There is no private key for decryption");
                return;
            }

            InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));
            JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);
            Object message = plainFact.nextObject();
            JcaPGPObjectFactory pgpFact=new JcaPGPObjectFactory(in);;
            if (message instanceof PGPCompressedData) {
                PGPCompressedData cData = (PGPCompressedData) message;
                pgpFact = new JcaPGPObjectFactory(cData.getDataStream());

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
                PGPOnePassSignatureList p1 = (PGPOnePassSignatureList) message;

                PGPOnePassSignature ops = p1.get(0);

                PGPLiteralData p2 = (PGPLiteralData) pgpFact.nextObject();

                InputStream dIn = p2.getInputStream();
                int ch;
                PGPPublicKey key = KeyRingHelper.getInstance().getPublicKey(ops.getKeyID());
                System.out.println("KEY ID" +key.getKeyID());
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
                    outFileName = p2.getFileName();
                    if (outFileName.length() == 0) {
                        outFileName = "defaultImeFajla";
                    }
                }
                OutputStream fOut = new FileOutputStream(outFileName);
                ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);
                while ((ch = dIn.read()) >= 0) {
                    ops.update((byte) ch);
                    fOut.write(ch);
                }

                fOut.close();

                PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();

                if (ops.verify(p3.get(0))) {
                    System.out.println("signature verified.");
                } else {
                    System.out.println("signature verification failed.");
                }

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
