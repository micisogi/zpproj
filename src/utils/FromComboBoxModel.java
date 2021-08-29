package utils;

import models.FromModel;

import javax.swing.*;

public class FromComboBoxModel extends DefaultComboBoxModel<FromModel> {
    public FromComboBoxModel(FromModel[] items){
        super(items);
    }

    @Override
    public FromModel getSelectedItem() {
        FromModel selectedJob = (FromModel) super.getSelectedItem();

        // do something with this job before returning...

        return selectedJob;
    }
}
