package utils;

import models.User;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;

import javax.swing.table.DefaultTableModel;
import java.util.List;

public class Utils {

    public static final String EMAIL_PATTERN =
            "^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@"
                    + "[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$";

    public static final String columnNames[] = {"Name", "Email", "Valid From", "Key-ID"};

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
        for (PGPPublicKey ppk : list
        ) {
            if(ppk.getUserIDs().hasNext()) {
                User u = new User(ppk.getUserIDs().next());
                Object o[] = new Object[4];
                o[0] = u.getName();
                o[1] =u.getEmail();
                o[2]= "PLACEHOLDER";
                o[3]="PLACEHOLDER";
                model.addRow(o);
            }
        }
    }
}
