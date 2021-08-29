package utils;

import models.User;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.util.encoders.Hex;

import javax.swing.table.DefaultTableModel;
import java.io.IOException;
import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class Utils {

    public ArrayList<User> users;

    public static final String EMAIL_PATTERN =
            "^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@"
                    + "[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$";

    public static final String columnNames[] = {"Name", "Email", "Valid From", "Key-ID", "Algorithm", "Type"};

    private static Utils instance;

    private Utils() {
        users = new ArrayList<>();
    }

    public ArrayList<User> getUsers() {
        return users;
    }

    /**
     * @return instance of representing singleton pattern
     */
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

    /**
     * A Util function used to format ID of keys
     *
     * @param name
     * @param email
     * @return
     */
    public String formatNameAndEmail(String name, String email) {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(name).append(" <").append(email).append(">");
        return stringBuilder.toString();
    }

    /** A Util function to refresh key table with new data
     * @param model
     */
    public static void refreshTable(DefaultTableModel model) {
        try {
            Utils.getInstance().pgpSecretKeyListToObject(KeyRingHelper.getInstance().getSecretKeyRingsFromFile(), model);
            Utils.getInstance().pgpPublicKeyListToObject(KeyRingHelper.getInstance().getPublicKeyRingsFromFile(), model);
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    /**
     * A Util function to put all the secret keys from the collection into the table
     * @param list
     * @param model
     */
    public void pgpSecretKeyListToObject(List<PGPSecretKey> list, DefaultTableModel model) {
        users.removeAll(users);
        SimpleDateFormat sdf = new SimpleDateFormat("dd.MM.yyyy hh:mm");
        User u = null;
        for (Iterator<PGPSecretKey> it = list.iterator(); it.hasNext(); ) {
            PGPSecretKey sk = it.next();
            Object o[] = new Object[columnNames.length];

            if (sk.getUserIDs().hasNext()) {
                u = new User(sk.getUserIDs().next());
                u.setDsaPubKey(sk.getPublicKey());
                u.setDsaSecretKey(sk);
                users.add(u);
            } else {
                u.setElgamalPubKey(sk.getPublicKey());
                u.setElgamalSecretKey(sk);
            }
            o[0] = u.getName();
            o[1] = u.getEmail();
            o[2] = sdf.format(sk.getPublicKey().getCreationTime());
            o[3] = Long.toHexString(sk.getKeyID());
            o[4] = sk.getPublicKey().getAlgorithm() == 17 ? "DSA" : "ElGamal";
            o[5] = "PRIVATE";
            model.addRow(o);
        }
    }
    /**
     * A Util function to put all the public keys from the collection into the table
     * @param list
     * @param model
     */
    public void pgpPublicKeyListToObject(List<PGPPublicKey> list, DefaultTableModel model) {
        SimpleDateFormat sdf = new SimpleDateFormat("dd-mm-yyyy");
        for (PGPPublicKey ppk : list
        ) {
            if (ppk.getUserIDs().hasNext()) {
                User u = new User(ppk.getUserIDs().next());
                users.add(u);
                Object o[] = new Object[columnNames.length];
                o[0] = u.getName();
                o[1] = u.getEmail();
                o[2] = sdf.format(ppk.getCreationTime());
                o[3] = Long.toHexString(ppk.getKeyID());
                o[4] = ppk.getAlgorithm() == 17 ? "DSA" : "ElGamal";
                o[5] = "PUBLIC";
                model.addRow(o);
            } else {
                User u = new User("");
                for (User k : users) {
                    if(k.getElgamalPubKey()!=null){
                        if (k.getElgamalPubKey().getKeyID() == ppk.getKeyID()) {
                            u = k;
                            break;
                        }
                    }

                }
                Object o[] = new Object[columnNames.length];
                o[0] = u.getName();
                o[1] = u.getEmail();
                o[2] = sdf.format(ppk.getCreationTime());
                o[3] = Long.toHexString(ppk.getKeyID());
                o[4] = ppk.getAlgorithm() == 17 ? "DSA" : "ElGamal";
                o[5] = "PUBLIC";
                model.addRow(o);
            }

        }
    }

    /**
     * A Util function to represent the keyID in HEX
     * @param hexString
     * @return
     */
    public long hexStringToLongID(String hexString) {
        return new BigInteger(hexString, 16).longValue();
    }

    /**
     * A Util function to insert a dot after a String. Used to append an extension.
     * @param old
     * @param toInsert
     * @return
     */
    public static String insertStringBeforeDot(String old, String toInsert) {
        int at = old.lastIndexOf(".");
        return old.substring(0, at) + toInsert + old.substring(at);
    }
}
