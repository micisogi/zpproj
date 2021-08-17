package utils;

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
}
