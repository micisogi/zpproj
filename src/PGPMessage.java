import models.User;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
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
            return KeyRingHelper.getInstance().getPrivateKey(from, passPhrase);
        } catch (IOException | PGPException e) {
//            e.printStackTrace();
            return null;
        }
    }

    public boolean verifyPassPhrase(){
        PGPPrivateKey pk = getPrivateKey();
        if(pk == null) return false;
        else return true;
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

    public void sendMessage(){
        if(authentication){

        }
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
}
