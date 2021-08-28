import models.User;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import utils.KeyRingHelper;
import utils.Utils;

import java.io.*;
import java.nio.Buffer;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

public class PGPMessage {
    private String message;
    String from;
    String sendTo;
    private boolean authentication, privacy, compression, conversion, des, idea;
    private String chipertext;
    User userfrom;
    User userSendTo;
    String passPhrase;
    PGPPrivateKey privateKey;

    public PGPMessage(String message,
                      String from,
                      String sendTo,
                      boolean authentication,
                      boolean privacy,
                      boolean compression,
                      boolean conversion,
                      boolean des,
                      boolean idea,
                      String passPhrase)
    {
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

        userfrom = User.getInfoFromUser(from.toString());
        userSendTo = User.getInfoFromUser(sendTo.toString());

    }

    public PGPPrivateKey getPrivateKey(){
        try {
            return privateKey = KeyRingHelper.getInstance().getPrivateKey(from, passPhrase);
        } catch (IOException | PGPException e) {
//            e.printStackTrace();
            return null;
        }
    }

    public boolean verifyPassPhrase(){
        PGPPrivateKey pk = getPrivateKey();
        if(pk == null) return false;
        else {
            System.out.println("VERIFIED SECRET KEY:" +pk.getKeyID());
            return true;
        }
    }

    public String getChipertext() {
        return chipertext;
    }

    public void setChipertext(String chipertext) {
        this.chipertext = chipertext;
    }

    public byte[] compress(String message) throws IOException{
        byte[] data = message.getBytes();
        PGPCompressedDataGenerator compressGen = new PGPCompressedDataGenerator( PGPCompressedData.ZIP );
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        OutputStream compressOut = compressGen.open( bos );
        OutputStream os =
                new PGPLiteralDataGenerator().open( compressOut, PGPLiteralData.BINARY, "", data.length, new Date() );
        os.write( data );
        os.close();
        compressGen.close();
        return bos.toByteArray();
    }

    public void authentication(String from, String sendTo, String alg){

    }

    public void privacy(String from, String sendTo, String alg){

    }

    public void compression(){

    }

    public void conversion(){

    }

    public void sendMessage() throws IOException, PGPException {
        if(authentication){
            PGPSecretKey secretKey = KeyRingHelper.getInstance().getSecretKey(from);
//            PGPPrivateKey privateKey = KeyRingHelper.getInstance().getPrivateKey(from, passPhrase);
//            PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1).setProvider("BC"));
//            signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
//
//            byte[] messageCharToArray = message.getBytes();
//            ByteArrayOutputStream encOut = new ByteArrayOutputStream();
//            OutputStream out = encOut;
//            out = new ArmoredOutputStream(out);
//
//            Iterator    it = secretKey.getPublicKey().getUserIDs();
//            if (it.hasNext())
//            {
//                PGPSignatureSubpacketGenerator  spGen = new PGPSignatureSubpacketGenerator();
//
//                spGen.setSignerUserID(false, (String)it.next());
//                signatureGenerator.setHashedSubpackets(spGen.generate());
//            }
//
//            signatureGenerator.update(messageCharToArray);
//
//            PGPSignature sig =  signatureGenerator.generate();

            String messageSignature = signMessageByteArray(message, secretKey,from,passPhrase);





            chipertext = String.valueOf(privateKey.getKeyID()) + message + messageSignature.toString();
        }
    }

    private static String signMessageByteArray(String message,
                                               PGPSecretKey secretKey,String from, String passPhrase) throws IOException,PGPException{

        byte[] messageCharArray = message.getBytes();

        ByteArrayOutputStream encOut = new ByteArrayOutputStream();
        OutputStream out = encOut;
        out = new ArmoredOutputStream(out);

        // Unlock the private key using the password

        PGPPrivateKey privateKey = KeyRingHelper.getInstance().getPrivateKey(from, passPhrase);

        // Signature generator, we can generate the public key from the private
        // key! Nifty!
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1).setProvider("BC"));
        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);

        Iterator it = secretKey.getPublicKey().getUserIDs();
        if (it.hasNext()) {
            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
            spGen.setSignerUserID(false, (String) it.next());
            signatureGenerator.setHashedSubpackets(spGen.generate());
        }

        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(
                PGPCompressedData.ZLIB);

        BCPGOutputStream bOut = new BCPGOutputStream(comData.open(out));

        signatureGenerator.generateOnePassVersion(false).encode(bOut);

        PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
        OutputStream lOut = lGen.open(bOut, PGPLiteralData.BINARY,
                PGPLiteralData.CONSOLE, messageCharArray.length, new Date());

        for (byte c : messageCharArray) {
            lOut.write(c);
            signatureGenerator.update(c);
        }

        lOut.close();
        /*
         * while ((ch = message.toCharArray().read()) >= 0) { lOut.write(ch);
         * sGen.update((byte) ch); }
         */
        lGen.close();

        signatureGenerator.generate().encode(bOut);

        comData.close();

        out.close();

        return encOut.toString();
    }
//
//
//        try {
//            OutputStream outmessage = new FileOutputStream("output.txt");
//            // Converts the string into bytes
//            byte[] dataBytes = data.getBytes();
//            // Writes data to the output stream
//            outmessage.write(dataBytes);
//            // Closes the output stream
//            PGPCompressedDataGenerator compGen = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
//            OutputStream compressedOut = compGen.open(outmessage, new byte[4096]);
//
//            PGPLiteralDataGenerator literalGen = new PGPLiteralDataGenerator();
//            OutputStream literalOut = literalGen.open(
//                    compressedOut,
//                    PGPLiteralData.BINARY,
//                    "",
//                    new Date(),
//                    new byte[4096]);
//
//            literalGen.close();
//            compGen.close();
//            outmessage.close();
//
//
//
//        }
//
//        catch (Exception e) {
//            e.getStackTrace();
//        }
//
//    }
}
