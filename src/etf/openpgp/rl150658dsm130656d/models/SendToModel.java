package etf.openpgp.rl150658dsm130656d.models;

import org.bouncycastle.openpgp.PGPPublicKey;

import javax.swing.*;

/**
 * A model class used to populate receiver dropdown list
 */
public class SendToModel extends DefaultListModel {

    String nameEmail;
    PGPPublicKey publicKey;

    public SendToModel(String ne, PGPPublicKey pk) {
        nameEmail = ne;
        publicKey = pk;
    }

    public String getNameEmail() {
        return nameEmail;
    }

    public PGPPublicKey getPublicKeyKey() {
        return publicKey;
    }

    @Override
    public String toString() {
        return Long.toHexString(publicKey.getKeyID());
    }
}
