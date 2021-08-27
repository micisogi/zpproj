package models;

import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import utils.Utils;

import java.util.Date;

public class User {
    private String name;
    private String email;
    private PGPPublicKey dsaPubKey;
    private PGPSecretKey dsaSecretKey;
    private PGPPublicKey elgamalPubKey;
    private PGPSecretKey elgamalSecretKey;
    private PGPKeyRing pubKeyRing;
    private PGPKeyRing secKeyRing;
    private Date date;
    private String nameAndEmail;
    private String password;

    public User(String nameAndEmail) {
        this.nameAndEmail = nameAndEmail;
        if (containsEmail() && (nameAndEmail.indexOf("<") < nameAndEmail.indexOf(">"))) {
            email = nameAndEmail.substring(nameAndEmail.indexOf("<") + 1);
            email = email.substring(0, email.indexOf(">"));
        } else {
            email = " ";
        }
        if (containsEmail()) {
            name = nameAndEmail.substring(0, nameAndEmail.indexOf("<") - 1);
        } else {
            name = nameAndEmail;
        }
    }

    public Date getDate() {
        return date;
    }

    public void setDate(Date date) {
        this.date = date;
    }

    public String getName() {
        return name;
    }

    public String getEmail() {
        return email;
    }

    public PGPPublicKey getDsaPubKey() {
        return dsaPubKey;
    }

    public void setDsaPubKey(PGPPublicKey dsaPubKey) {
        this.dsaPubKey = dsaPubKey;
    }

    public PGPSecretKey getDsaSecretKey() {
        return dsaSecretKey;
    }

    public void setDsaSecretKey(PGPSecretKey dsaSecretKey) {
        this.dsaSecretKey = dsaSecretKey;
    }

    public PGPPublicKey getElgamalPubKey() {
        return elgamalPubKey;
    }

    public void setElgamalPubKey(PGPPublicKey elgamalPubKey) {
        this.elgamalPubKey = elgamalPubKey;
    }

    public PGPSecretKey getElgamalSecretKey() {
        return elgamalSecretKey;
    }

    public String getNameAndEmail() {
        return nameAndEmail;
    }

    public void setNameAndEmail(String nameAndEmail) {
        this.nameAndEmail = nameAndEmail;
    }

    public void setElgamalSecretKey(PGPSecretKey elgamalSecretKey) {
        this.elgamalSecretKey = elgamalSecretKey;
    }

    public PGPKeyRing getPubKeyRing() {
        return pubKeyRing;
    }

    public void setPubKeyRing(PGPKeyRing pubKeyRing) {
        this.pubKeyRing = pubKeyRing;
    }

    public PGPKeyRing getSecKeyRing() {
        return secKeyRing;
    }

    public void setSecKeyRing(PGPKeyRing secKeyRing) {
        this.secKeyRing = secKeyRing;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    private boolean containsEmail() {
        return nameAndEmail.contains("<") && nameAndEmail.contains(">");
    }

    public static User getInfoFromUser(String email){
        for (User u : Utils.getInstance().users){
            if(u.getNameAndEmail().equals(email)) return u;
        }
        return null;
    }
}
