import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class mainGUI extends JFrame {
    private JPanel mainPanel;
    private JTabbedPane tabbedPane1;
    private JPanel Drugi;
    private JPanel Prvi;
    private JTextField email;
    private JRadioButton DSARadioButton;
    private JRadioButton elGamalRadioButton;
    private JButton generateButton;
    private JTextField name;
    private JTable table1;
    private JScrollPane scrollPane;

    public mainGUI(String title) {
        super(title);

        ButtonGroup algorithmChoiceButtons = new ButtonGroup();
        algorithmChoiceButtons.add(DSARadioButton);
        algorithmChoiceButtons.add(elGamalRadioButton);

//        generateButton.addActionListener(new ActionListener() {
//            @Override
//            public void actionPerformed(ActionEvent e) {
//                DSAKeyRingGenerator dsa= new DSAKeyRingGenerator();
//                try {
//                    dsa.generateDsaKeyPair(1024);
//                } catch (Exception exception) {
//                    exception.printStackTrace();
//                }
//            }
//        });


        initTable();
        generateButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                if (!email.getText().matches(Utils.EMAIL_PATTERN)) {
                    JOptionPane.showMessageDialog(null, "Email format pogresan");
                    return;
                }
                if (name.getText().isEmpty() || email.getText().isEmpty()) {
                    JOptionPane.showMessageDialog(null, "Neispravno uneti podaci");
                } else {
                    System.out.println(Utils.getInstance().formatNameAndEmail(name.getText(), email.getText()));
//                    JOptionPane.showMessageDialog(null, "Kljucevi su izgenerisani");
                }
                DefaultTableModel model = (DefaultTableModel) table1.getModel();
              model.addRow(new String[Utils.columnNames.length]);
            }
        });
        this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        this.setContentPane(mainPanel);
        this.pack();
    }

    private void initTable() {
        TableModel dataModel = new DefaultTableModel(Utils.columnNames,0);

        table1 = new JTable(dataModel);
        table1.setPreferredScrollableViewportSize(new Dimension(300, 100));
        scrollPane.setViewportView(table1);
    }

    public static void main(String[] args) throws Exception {

        JFrame frame = new mainGUI("ZP PROJEKAT UBI ME");
        frame.setSize(1200, 700);
        frame.setVisible(true);
    }

}
