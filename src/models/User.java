package models;

import java.util.Date;

public class User {
    private String name;
    private String email;
    private String pubKeyID;
    private Date date;

    public String getPubKeyID() {
        return pubKeyID;
    }

    public void setPubKeyID(String pubKeyID) {
        this.pubKeyID = pubKeyID;
    }

    public Date getDate() {
        return date;
    }

    public void setDate(Date date) {
        this.date = date;
    }

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
