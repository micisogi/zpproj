package utils;

import models.User;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.util.encoders.Hex;

import javax.swing.table.DefaultTableModel;
import java.text.SimpleDateFormat;
import java.util.Iterator;
import java.util.List;

public class Utils {

    public static final String EMAIL_PATTERN =
            "^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@"
                    + "[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$";

    public static final String columnNames[] = {"Name", "Email", "Valid From", "Public Key-ID", "Private Key-ID", "Algorithm"};

    private static Utils instance;

    private Utils() {
    }

    public static Utils getInstance() {
        if (instance == null) {
            synchronized (Utils.class) {
                if (instance == null) {
                    instance = new Utils();
                }
            }
        }
        return instance;
    }

    public String formatNameAndEmail(String name, String email) {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(name).append(" <").append(email).append(">");
        return stringBuilder.toString();
    }

    public void pgpSecretKeyListToObject(List<PGPSecretKey> list, DefaultTableModel model) {
//        System.out.println("Secret List"+list.size());
        model.getDataVector().removeAllElements();
        SimpleDateFormat sdf = new SimpleDateFormat("dd.MM.yyyy hh:mm");
        User u = null;
        for (Iterator<PGPSecretKey> it = list.iterator(); it.hasNext(); ) {
            PGPSecretKey sk = it.next();
            Object o[] = new Object[columnNames.length];

            if(sk.getUserIDs().hasNext()) {
                u = new User(sk.getUserIDs().next());
            }
            o[0] = u.getName();
            o[1] = u.getEmail();
            o[2] = sdf.format(sk.getPublicKey().getCreationTime());
            o[3] = Long.toHexString(sk.getPublicKey().getKeyID());
            o[4] = Long.toHexString(sk.getKeyID());
            o[5] = sk.getPublicKey().getAlgorithm() == 17? "DSA": "ElGamal";
            model.addRow(o);
        }
//        for (PGPSecretKey sk : list) {
//            if (sk.getUserIDs().hasNext()) {
////                System.out.println("Secret List if"+list.size());
//                User u = new User(sk.getUserIDs().next());
//                Object o[] = new Object[columnNames.length];
//                o[0] = u.getName();
//                o[1] = u.getEmail();
//                o[2] = sdf.format(sk.getPublicKey().getCreationTime());
//                o[3] = Long.toHexString(sk.getPublicKey().getKeyID());
//                o[4] = Long.toHexString(sk.getKeyID());
//                o[5] = sk.getKeyEncryptionAlgorithm();
//                model.addRow(o);
//
//            }
//        }
    }

    public void pgpPublicKeyListToObject(List<PGPPublicKey> list, DefaultTableModel model) {
        model.getDataVector().removeAllElements();
        SimpleDateFormat sdf = new SimpleDateFormat("dd-mm-yyyy");
        for (PGPPublicKey ppk : list
        ) {
            if(ppk.getUserIDs().hasNext()) {
                User u = new User(ppk.getUserIDs().next());
                Object o[] = new Object[columnNames.length];
                o[0] = u.getName();
                o[1] =u.getEmail();
                o[2]= sdf.format(ppk.getCreationTime());
                o[3]= Long.toHexString(ppk.getKeyID());
                o[4] = ppk.isMasterKey();
                model.addRow(o);
            }
        }
    }
}
