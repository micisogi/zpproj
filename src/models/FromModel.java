package models;

import org.bouncycastle.openpgp.PGPSecretKey;

/**
 * A model class used to populate sender dropdown list
 */
public class FromModel {
    String nameEmail;
    PGPSecretKey secretKey;

    public FromModel(String ne, PGPSecretKey pk) {
        nameEmail = ne;
        secretKey = pk;
    }

    public String getNameEmail() {
        return nameEmail;
    }

    public PGPSecretKey getSecretKey() {
        return secretKey;
    }

    @Override
    public String toString() {
        return nameEmail;
    }
}
