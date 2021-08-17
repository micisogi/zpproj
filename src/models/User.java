package models;

public class User {
    private String name;
    private String email;

    public User(String nameAndEmail) {
        email = nameAndEmail.substring(nameAndEmail.indexOf("<") + 1);
        email = email.substring(0, email.indexOf(">"));
        name = nameAndEmail.substring(0, nameAndEmail.indexOf(" "));
    }

    public String getName() {
        return name;
    }

    public String getEmail() {
        return email;
    }
}
