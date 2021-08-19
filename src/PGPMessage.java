import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.Buffer;
import java.util.Date;

public class PGPMessage {
    private String message;
    private String email;
    private boolean authentication, privacy, compression, conversion, des, idea;
    private String chipertext;

    public PGPMessage(String message,
                      String email,
                      boolean authentication,
                      boolean privacy,
                      boolean compression,
                      boolean conversion,
                      boolean des,
                      boolean idea)
    {
        this.message = message;
        this.email = email;
        this.authentication = authentication;
        this.privacy = privacy;
        this.compression = compression;
        this.conversion = conversion;
        this.des = des;
        this.idea = idea;
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
