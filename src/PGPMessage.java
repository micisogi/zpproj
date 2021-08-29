import models.User;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import utils.KeyRingHelper;
import utils.Utils;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.io.*;
import java.nio.Buffer;
import java.nio.charset.StandardCharsets;
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
            String messageSignature = signMessageByteArray(message, secretKey,from,passPhrase);

            chipertext = messageSignature;
        }
    }

    private static String signMessageByteArray(String message,
                                               PGPSecretKey secretKey,
                                               String from,
                                               String passPhrase) throws IOException,PGPException {

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

    public static void verifyFile(
            InputStream        in)
            throws Exception
    {
        in = PGPUtil.getDecoderStream(in);

        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(in);

        PGPCompressedData           c1 = (PGPCompressedData)pgpFact.nextObject();

        pgpFact = new JcaPGPObjectFactory(c1.getDataStream());

        PGPOnePassSignatureList     p1 = (PGPOnePassSignatureList)pgpFact.nextObject();

        PGPOnePassSignature         ops = p1.get(0);

        PGPLiteralData              p2 = (PGPLiteralData)pgpFact.nextObject();

        InputStream                 dIn = p2.getInputStream();
        int                         ch;
        KeyRingHelper.getInstance().getPublicKey(ops.getKeyID());

        PGPPublicKey                key =    KeyRingHelper.getInstance().getPublicKey(ops.getKeyID());
        FileOutputStream            out = new FileOutputStream(p2.getFileName());

        ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);

        while ((ch = dIn.read()) >= 0)
        {
            ops.update((byte)ch);
            out.write(ch);
        }

        out.close();

        PGPSignatureList            p3 = (PGPSignatureList)pgpFact.nextObject();

        if (ops.verify(p3.get(0)))
        {
            System.out.println("signature verified.");
        }
        else
        {
            System.out.println("signature verification failed.");
        }
    }




//            byte myEncoded[] = chiphertext.getEncoded();
//            try (FileOutputStream fos = new FileOutputStream(filePath)) {
//                fos.write(myEncoded);
//            }
//            try {
//                InputStream fIn = new BufferedInputStream(new FileInputStream(absolutePath));
//                ArmoredOutputStream aOut = new ArmoredOutputStream(out);
//            } catch (FileNotFoundException e) {
//                e.printStackTrace();
//            }
//
//            aOut.beginClearText(digest);

//            try {

//                DefaultTableModel model = (DefaultTableModel) table1.getModel();
//                int iDColumn = 3;
//                int row = table1.getSelectedRow();
//                String hexValue = table1.getModel().getValueAt(row, iDColumn).toString();
//            KeyRingHelper.getInstance().exportPublicKeyRing(hexValue, Utils.insertStringBeforeDot(absolutePath, "_pub"));
//                KeyRingHelper.getInstance().exportSecretKeyRing(hexValue, Utils.insertStringBeforeDot(absolutePath, "_sec"));


//            } catch (IOException e) {
//                e.printStackTrace();
//            } catch (PGPException e) {
//                try {
////                    KeyRingHelper.getInstance().readSecretKey(selectedFile.getAbsolutePath());
////                } catch (IOException ioException) {
////                    ioException.printStackTrace();
////                } catch (PGPException pgpException) {
//                    pgpException.printStackTrace();
//                }
//                e.printStackTrace();
//            }

}
