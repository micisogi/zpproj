package utils;

import models.User;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.util.encoders.Hex;

import javax.swing.table.DefaultTableModel;
import java.text.SimpleDateFormat;
import java.util.List;

public class Utils {

    public static final String EMAIL_PATTERN =
            "^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@"
                    + "[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$";

    public static final String columnNames[] = {"Name", "Email", "Valid From", "Key-ID", "Type"};

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
                o[4] = "PLACEHOLDER";
                model.addRow(o);
            }
        }
    }
}
