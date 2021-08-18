package models;

import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;

import java.util.Date;

public class User {
    private PGPPublicKeyRing publicKeyRing;
    private PGPPrivateKey privateKeyRing;
    private String name;
    private String email;
    private PGPPublicKey dsaPubKey;
    private PGPSecretKey dsaSecretKey;
    private PGPPublicKey elgamalPubKey;
    private PGPSecretKey elgamalSecretKey;
    private Date date;

    public User(String nameAndEmail) {
        email = nameAndEmail.substring(nameAndEmail.indexOf("<") + 1);
        email = email.substring(0, email.indexOf(">"));
        name = nameAndEmail.substring(0, nameAndEmail.indexOf(" "));
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

    public void setElgamalSecretKey(PGPSecretKey elgamalSecretKey) {
        this.elgamalSecretKey = elgamalSecretKey;
    }

    public PGPPrivateKey getPrivateKeyRing() {
        return privateKeyRing;
    }

    public void setPrivateKeyRing(PGPPrivateKey privateKeyRing) {
        this.privateKeyRing = privateKeyRing;
    }

    public PGPPublicKeyRing getPublicKeyRing() {
        return publicKeyRing;
    }

    public void setPublicKeyRing(PGPPublicKeyRing publicKeyRing) {
        this.publicKeyRing = publicKeyRing;
    }
}
