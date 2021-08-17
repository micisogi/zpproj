import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import utils.Utils;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Enumeration;

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
    private JTextField sendTo;
    private JButton sendButton;
    private JCheckBox authenticationCheckBox;
    private JCheckBox privacyCheckBox;
    private JCheckBox compressionCheckBox;
    private JTextArea message;
    private JTextArea chipertext;
    private JRadioButton DESRadioButton;
    private JRadioButton IDEARadioButton;
    private JTable table1;
    private JScrollPane scrollPane;
    private JButton deleteButton;
    private JButton importButton;
    private JButton exportButton;
    private ButtonGroup dsaButtonGroup;
    private ButtonGroup elGamalButtonGroup;

    public mainGUI(String title) {
        super(title);

        initDsaButtonGroup();
        initElGamalButtonGroup();
        initTable();
        initDeleteButton();
        initGenerateButton();
        initImportButton();

        this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        this.setContentPane(mainPanel);
        this.pack();
    }

    private void initElGamalButtonGroup() {
        elGamalButtonGroup = new ButtonGroup();
        elGamalButtonGroup.add(elGamal1024);
        elGamalButtonGroup.add(elGamal2048);
        elGamalButtonGroup.add(elGamal4096);
        elGamal1024.setSelected(true);
    }

    private void initDsaButtonGroup() {
        dsaButtonGroup = new ButtonGroup();
        dsaButtonGroup.add(DSA1024);
        dsaButtonGroup.add(DSA2048);
        DSA1024.setSelected(true);
    }

    private void initImportButton() {
        importButton.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent arg0) {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setCurrentDirectory(new File(System.getProperty("user.home")));
                int result = fileChooser.showOpenDialog(mainPanel);
                if (result == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = fileChooser.getSelectedFile();
                    try {
                        KeyRingGenerator.readPublicKey(selectedFile.getAbsolutePath());
                    } catch (IOException e) {
                        e.printStackTrace();
                    } catch (PGPException e) {
                        e.printStackTrace();
                    }
                }

            }
        });
    }

    private void initGenerateButton() {
        generateButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                DefaultTableModel model = (DefaultTableModel) table1.getModel();
                Object testStrings[] = {"Name", "Email", "Valid From", "Key-ID"};
                model.addRow(testStrings);
                if (!email.getText().matches(Utils.EMAIL_PATTERN)) {
                    JOptionPane.showMessageDialog(null, "Email format pogresan");
                    return;
                }
                if (name.getText().isEmpty() || email.getText().isEmpty()) {
                    JOptionPane.showMessageDialog(null, "Neispravno uneti podaci");
                } else {
                    System.out.println(Utils.getInstance().formatNameAndEmail(name.getText(), email.getText()));
                    DSAElGamalKeyRingGenerator dsael = new DSAElGamalKeyRingGenerator();
                    System.out.println("DSA" + getSelectedButtonText(dsaButtonGroup));
                    Integer dsaSize = Integer.parseInt(getSelectedButtonText(dsaButtonGroup));
                    Integer elGamalSize = Integer.parseInt(getSelectedButtonText(elGamalButtonGroup));
                    String passPhrase = JOptionPane.showInputDialog("Enter a password for the private key");
                    System.out.println(passPhrase);
                    try {
                        dsael.generateDSAELGamalKeyRing(dsaSize, elGamalSize, name.getText(), email.getText(), passPhrase);
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

    private void initDeleteButton() {
        deleteButton.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent arg0) {
                // check for selected row first
                if (table1.getSelectedRow() != -1) {
                    // remove selected row from the model
                    DefaultTableModel model = (DefaultTableModel) table1.getModel();
                    System.out.println(table1.getSelectedRow());
                    model.removeRow(table1.getSelectedRow());
                } else {
                    JOptionPane.showMessageDialog(null, "You have to choose a key to delete");
                }
            }
        });
    }

    private void initTable() {
        TableModel dataModel = new DefaultTableModel(Utils.columnNames, 0);
        table1 = new JTable(dataModel);
        table1.setPreferredScrollableViewportSize(new Dimension(300, 100));
        table1.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        scrollPane.setViewportView(table1);
    }

    public String getSelectedButtonText(ButtonGroup buttonGroup) {
        for (Enumeration<AbstractButton> buttons = buttonGroup.getElements(); buttons.hasMoreElements(); ) {
            AbstractButton button = buttons.nextElement();

            if (button.isSelected()) {
                return button.getText();
            }
        }

        return null;
    }
}
