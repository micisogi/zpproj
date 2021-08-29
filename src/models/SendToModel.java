package models;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

public class SendToModel {

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
