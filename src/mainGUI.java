import models.FromModel;
import models.SendToModel;
import models.User;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import utils.KeyRingHelper;
import utils.Utils;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * Class used by the java swing to draw all the elements
 */
public class mainGUI extends JFrame {
    private JPanel mainPanel;
    private JTabbedPane tabbedPane1;
    private JPanel Drugi;
    private JPanel Prvi;
    private JTextField email;
    private JRadioButton DSA1024;
    private JRadioButton elGamal4096;
    private JButton generateButton;
    private JTextField name;
    private JRadioButton DSA2048;
    private JRadioButton elGamal2048;
    private JRadioButton elGamal1024;
    private JButton sendButton;
    private JCheckBox authenticationCheckBox;
    private JCheckBox privacyCheckBox;
    private JCheckBox compressionCheckBox;
    private JTextArea message;
    private JRadioButton DESRadioButton;
    private JRadioButton IDEARadioButton;
    private JTable table1;
    private JScrollPane scrollPane;
    private JButton deleteButton;
    private JButton importButton;
    private JButton exportButton;
    private JEditorPane chiphertext;
    private JCheckBox conversionCheckBox;
    private JComboBox<FromModel> from;
    private JList sendTo;
    private JButton receive;
    private ButtonGroup dsaButtonGroup;
    private ButtonGroup elGamalButtonGroup;
    private ButtonGroup symetricButtonGroup;

    /**
     * @param title
     * @throws IOException
     */
    public mainGUI(String title) throws IOException {
        super(title);

        initDsaButtonGroup();
        initElGamalButtonGroup();
        initSymetricAlgsRadio();

        initTable();
        initDeleteButton();
        initGenerateButton();
        initImportButton();
        initExportButton();
        initSendButton();
        initReceiveButton();
        initDropDowns();


        this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        this.setContentPane(mainPanel);
        this.pack();
    }

    /**
     * Function used to instantiate symetric algorithm radio buttons
     */
    private void initSymetricAlgsRadio() {
        symetricButtonGroup = new ButtonGroup();
        symetricButtonGroup.add(IDEARadioButton);
        symetricButtonGroup.add(DESRadioButton);
        DESRadioButton.setSelected(true);
    }

    /**
     * Function used to instantiate drop down menus
     */
    private void initDropDowns() {
        initFromDropdown();
        initSendToDropdown();
    }

    /**
     * Function used to instantiate recipient drop down menu
     */
    private void initSendToDropdown() {
        try {
            List<PGPPublicKey> pgpPublicKeyList = KeyRingHelper.getInstance().getPublicKeyRingsFromFile();
            ArrayList<PGPPublicKey> listOfKeysForEncription = new ArrayList<>();
            int k = 0;
            for (int i = 0; i < pgpPublicKeyList.size(); i++) {
                if (pgpPublicKeyList.get(i).isEncryptionKey()) {
                    listOfKeysForEncription.add(pgpPublicKeyList.get(i));
                }
            }
            DefaultListModel<SendToModel> myModel = new DefaultListModel<SendToModel>();
            SendToModel[] models = new SendToModel[listOfKeysForEncription.size()];
            for (int i = 0; i < models.length; i++) {
                PGPPublicKey psk = listOfKeysForEncription.get(i);
                if (psk.getUserIDs().hasNext()) {
                    myModel.addElement(new SendToModel(psk.getUserIDs().next(), psk));
                } else {
                    myModel.addElement(new SendToModel(null, psk));
                }
            }
            sendTo.setSelectionModel(new DefaultListSelectionModel() {
                @Override
                public void setSelectionInterval(int index0, int index1) {
                    if (super.isSelectedIndex(index0)) {
                        super.removeSelectionInterval(index0, index1);
                    } else {
                        super.addSelectionInterval(index0, index1);
                    }
                }
            });
            sendTo.setModel(myModel);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Function used to instantiate sender drop down menu
     */
    private void initFromDropdown() {
        try {
            List<PGPSecretKey> pgpSecretKeyList = KeyRingHelper.getInstance().getSecretKeyRingsFromFile();
            ArrayList<PGPSecretKey> listOfKeysForSigning = new ArrayList<>();
            int k = 0;
            for (int i = 0; i < pgpSecretKeyList.size(); i++) {
                if (pgpSecretKeyList.get(i).isSigningKey()) {
                    listOfKeysForSigning.add(pgpSecretKeyList.get(i));
                }
            }
            FromModel[] models = new FromModel[listOfKeysForSigning.size()];
            for (int i = 0; i < models.length; i++) {
                PGPSecretKey psk = listOfKeysForSigning.get(i);
                models[i] = new FromModel(psk.getUserIDs().next(), psk);
            }
            DefaultComboBoxModel myModel = new DefaultComboBoxModel<>(models);

            from.setModel(myModel);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Function used to instantiate receive button
     */
    private void initReceiveButton() {
        receive.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setCurrentDirectory(new File(System.getProperty("user.home")));
                int result = fileChooser.showOpenDialog(mainPanel);
                if (result == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = fileChooser.getSelectedFile();
                    String absolutePath = selectedFile.getAbsolutePath();
                    try {
                        InputStream in = new BufferedInputStream(new FileInputStream(absolutePath));
                        PGPMessage.decrypt(in, mainPanel);
//                        if (PGPMessage.verifyFile(fis)) {
//                            JOptionPane.showMessageDialog(null, "Signature is valid.");
//                            return;
//                        } else {
//                            JOptionPane.showMessageDialog(null, "Signature verification failed.");
//                            return;
//                        }
                    } catch (FileNotFoundException fileNotFoundException) {
                    } catch (Exception exception) {
                    }
                }
            }
        });
    }

    /**
     * Function used to instantiate export button
     */
    private void initExportButton() {
        exportButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                if (table1.getSelectedRow() != -1) {
                    JFileChooser fileChooser = new JFileChooser();
                    fileChooser.setCurrentDirectory(new File(System.getProperty("user.home")));
                    fileChooser.setFileFilter(new FileNameExtensionFilter("*.asc", "asc"));
                    int result = fileChooser.showOpenDialog(mainPanel);
                    if (result == JFileChooser.APPROVE_OPTION) {
                        File selectedFile = fileChooser.getSelectedFile();
                        String absolutePath = selectedFile.getAbsolutePath();
                        if (!absolutePath.substring(absolutePath.lastIndexOf(".") + 1).equals("asc"))
                            absolutePath += ".asc";

                        try {

                            DefaultTableModel model = (DefaultTableModel) table1.getModel();
                            int iDColumn = 3;
                            int row = table1.getSelectedRow();
                            String hexValue = table1.getModel().getValueAt(row, iDColumn).toString();
                            KeyRingHelper.getInstance().exportPublicKeyRing(hexValue, Utils.insertStringBeforeDot(absolutePath, "_pub"));
                            KeyRingHelper.getInstance().exportSecretKeyRing(hexValue, Utils.insertStringBeforeDot(absolutePath, "_sec"));


                        } catch (IOException e) {
                            e.printStackTrace();
                        } catch (PGPException e) {
                            try {
                                KeyRingHelper.getInstance().readSecretKey(selectedFile.getAbsolutePath());
                            } catch (IOException ioException) {
                                ioException.printStackTrace();
                            } catch (PGPException pgpException) {
                                pgpException.printStackTrace();
                            }
                            e.printStackTrace();
                        }
                    }
                } else {
                    JOptionPane.showMessageDialog(null, "You have to choose a key to export");
                }
            }
        });

    }

    /**
     * Function used to instantiate ElGamal size radio buttons
     */
    private void initElGamalButtonGroup() {
        elGamalButtonGroup = new ButtonGroup();
        elGamalButtonGroup.add(elGamal1024);
        elGamalButtonGroup.add(elGamal2048);
        elGamalButtonGroup.add(elGamal4096);
        elGamal1024.setSelected(true);
    }

    /**
     * Function used to instantiate DSA size radio buttons
     */
    private void initDsaButtonGroup() {
        dsaButtonGroup = new ButtonGroup();
        dsaButtonGroup.add(DSA1024);
        dsaButtonGroup.add(DSA2048);
        DSA1024.setSelected(true);
    }

    /**
     * Function used to instantiate import button
     */
    private void initImportButton() {
        importButton.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent arg0) {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setCurrentDirectory(new File(System.getProperty("user.home")));
                DefaultTableModel model = (DefaultTableModel) table1.getModel();
                int result = fileChooser.showOpenDialog(mainPanel);
                if (result == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = fileChooser.getSelectedFile();
                    try {
                        KeyRingHelper.getInstance().readPublicKey(selectedFile.getAbsolutePath());
                    } catch (IOException e) {
                        try {
                            KeyRingHelper.getInstance().readSecretKey(selectedFile.getAbsolutePath());
                        } catch (IOException ioException) {
                            ioException.printStackTrace();
                        } catch (PGPException pgpException) {
                            pgpException.printStackTrace();
                        }
                        e.printStackTrace();
                    } catch (PGPException e) {
                        e.printStackTrace();
                    }
                }
                Utils.refreshTable(model);
                initDropDowns();

            }
        });
    }

    /**
     * Function used to instantiate generate button
     */
    private void initGenerateButton() {
        generateButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                DefaultTableModel model = (DefaultTableModel) table1.getModel();
                if (!email.getText().matches(Utils.EMAIL_PATTERN)) {
                    JOptionPane.showMessageDialog(null, "Email format pogresan");
                    return;
                }
                if (name.getText().isEmpty() || email.getText().isEmpty()) {
                    JOptionPane.showMessageDialog(null, "Neispravno uneti podaci");
                } else {
                    DSAElGamalKeyRingGenerator dsael = new DSAElGamalKeyRingGenerator();
                    Integer dsaSize = Integer.parseInt(getSelectedButtonText(dsaButtonGroup));
                    Integer elGamalSize = Integer.parseInt(getSelectedButtonText(elGamalButtonGroup));
                    String passPhrase = JOptionPane.showInputDialog("Enter a password for the private key");
                    try {
                        dsael.generateDSAELGamalKeyRing(dsaSize, elGamalSize, name.getText(), email.getText(), passPhrase);
                        Utils.refreshTable(model);
                        initDropDowns();

                    } catch (NoSuchProviderException e) {
                        e.printStackTrace();
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                    } catch (InvalidAlgorithmParameterException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    } catch (PGPException e) {
                        e.printStackTrace();
                    }
                    JOptionPane.showMessageDialog(null, "Keys have been generated");
                }
            }
        });
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        JFrame frame = new mainGUI("ZP PROJEKAT UBI ME");
        frame.setSize(800, 500);
        frame.setVisible(true);
    }

    /**
     * Function used to instantiate delete button
     */
    private void initDeleteButton() {
        deleteButton.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent arg0) {
                DefaultTableModel model = (DefaultTableModel) table1.getModel();
                // check for selected row first
                if (table1.getSelectedRow() != -1) {
                    // remove selected row from the model
                    int iDColumn = 3;
                    int row = table1.getSelectedRow();
                    String hexValue = table1.getModel().getValueAt(row, iDColumn).toString();
                    try {
                        KeyRingHelper.getInstance().deleteKeyRing(hexValue);
                        model.removeRow(table1.getSelectedRow());
                    } catch (IOException e) {
                        e.printStackTrace();

                    }
                } else {
                    JOptionPane.showMessageDialog(null, "You have to choose a key to delete");
                }
                initDropDowns();
            }
        });
    }

    /**
     * Function used to instantiate the key rings table
     *
     * @throws IOException
     */
    private void initTable() throws IOException {
        TableModel dataModel = new DefaultTableModel(Utils.columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        table1 = new JTable(dataModel);
        table1.setPreferredScrollableViewportSize(new Dimension(300, 100));
        table1.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        scrollPane.setViewportView(table1);
        DefaultTableModel model = (DefaultTableModel) table1.getModel();
        Utils.refreshTable(model);
    }

    /**
     * Function used to instantiate the send message button
     */
    private void initSendButton() {

        from.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (e.getSource() == from) {
                    System.out.println(from.getSelectedItem());
                }
            }
        });

        sendButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent a) {
                int symAlg = 2;
                if (!privacyCheckBox.isSelected() && !authenticationCheckBox.isSelected()
                        && !compressionCheckBox.isSelected() && !conversionCheckBox.isSelected()) {
                    JOptionPane.showMessageDialog(null, "Morate izabrati neku akciju");
                    return;
                }
                if (privacyCheckBox.isSelected()) {
                    String alg = getSelectedButtonText(symetricButtonGroup);
                    switch (alg) {
                        case "3DES": {
                            symAlg = SymmetricKeyAlgorithmTags.TRIPLE_DES;
                            break;
                        }
                        case "IDEA": {
                            symAlg = SymmetricKeyAlgorithmTags.IDEA;
                            break;
                        }
                    }
                }

                if (privacyCheckBox.isSelected() && sendTo.isSelectionEmpty()) {
                    JOptionPane.showMessageDialog(null, "Morate izabrati posaljioca.");
                    return;
                }
                if (privacyCheckBox.isSelected() && sendTo.isSelectionEmpty() == true) {
                    JOptionPane.showMessageDialog(null, "Morate izabrati primaoca.");
                    return;
                }
                if (compressionCheckBox.isSelected() && !authenticationCheckBox.isSelected() && !privacyCheckBox.isSelected() && message.getText().isEmpty()) {
                    JOptionPane.showMessageDialog(null, "Morate uneti poruku.");
                    return;
                }
                if (conversionCheckBox.isSelected() && !authenticationCheckBox.isSelected() && !privacyCheckBox.isSelected() && message.getText().isEmpty()) {
                    JOptionPane.showMessageDialog(null, "Morate uneti poruku.");
                    return;
                }

                String passPhrase = null;
                if (authenticationCheckBox.isSelected()) {
                    passPhrase = JOptionPane.showInputDialog("Enter a password for the private key");
                    if (passPhrase == null) {
                        return;
                    }
                }

                FromModel fr = (FromModel) from.getSelectedItem();
                System.out.println(Long.toHexString(fr.getSecretKey().getKeyID()));
                PGPMessage pgpmsg = new PGPMessage(
                        message.getText(),
                        fr.getSecretKey().getKeyID(),
                        getSelectedListItems(sendTo),
                        authenticationCheckBox.isSelected(),
                        privacyCheckBox.isSelected(),
                        compressionCheckBox.isSelected(),
                        conversionCheckBox.isSelected(),
                        DESRadioButton.isSelected(),
                        symAlg,
                        IDEARadioButton.isSelected(),
                        passPhrase);

                if (authenticationCheckBox.isSelected() && !pgpmsg.verifyPassPhrase()) {
                    JOptionPane.showMessageDialog(null, "Pogresna lozinka.");
                    return;
                }

                try {
                    pgpmsg.setFilepath(getFilePath());
                    pgpmsg.sendMessage();
                    FileReader reader = new FileReader(pgpmsg.getFilepath());
                    BufferedReader br = new BufferedReader(reader);
                    chiphertext.read(br, null);
                    br.close();
                    chiphertext.requestFocus();
//                    chiphertext.setText(pgpmsg.getChipherText());
//                    byte[] msgByte = pgpmsg.getChiphertextInBytes();
//                    saveMessageByte(msgByte);
//                    chiphertext.setText(pgpmsg.getChipertext());
//                    saveMessage(chiphertext.getText());

                } catch (IOException | PGPException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (SignatureException e) {
                    e.printStackTrace();
                } catch (NoSuchProviderException e) {
                    e.printStackTrace();
                }
            }
        });
    }

    /**
     * Function used to return a String value of the radio button selected inside the radio group
     *
     * @param buttonGroup
     * @return
     */
    public String getSelectedButtonText(ButtonGroup buttonGroup) {
        for (Enumeration<AbstractButton> buttons = buttonGroup.getElements(); buttons.hasMoreElements(); ) {
            AbstractButton button = buttons.nextElement();

            if (button.isSelected()) {
                return button.getText();
            }
        }
        return null;
    }

    /**
     * function used to save a  OpenPGP message into a text file
     */

    public String getFilePath() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setCurrentDirectory(new File(System.getProperty("user.home")));
        fileChooser.setFileFilter(new FileNameExtensionFilter("*.gpg", "gpg"));
        int result = fileChooser.showOpenDialog(mainPanel);
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            String absolutePath = selectedFile.getAbsolutePath();
            if (!absolutePath.substring(absolutePath.lastIndexOf(".") + 1).equals("gpg"))
                absolutePath += ".gpg";

            return absolutePath;
        }
        return null;
    }

    /**
     * A function used to get list of selected recipients
     *
     * @param list
     * @return
     */
    private List<Long> getSelectedListItems(JList<SendToModel> list) {
        ArrayList<Long> returnList = new ArrayList<>();
        list.getSelectedValuesList().forEach(model -> {
            returnList.add(model.getPublicKeyKey().getKeyID());
        });
        return returnList;
    }

}
