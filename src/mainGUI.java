import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class mainGUI extends JFrame{
    private JPanel mainPanel;
    private JTabbedPane tabbedPane1;
    private JPanel Drugi;
    private JPanel Prvi;
    private JTextField email;
    private JRadioButton DSARadioButton;
    private JRadioButton elGamalRadioButton;
    private JButton generateButton;
    private JTextField name;

    public mainGUI(String title){
        super(title);

        generateButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                DSAKeyRingGenerator dsa= new DSAKeyRingGenerator();
                try {
                    dsa.generateDsaKeyPair(1024);
                } catch (Exception exception) {
                    exception.printStackTrace();
                }
            }
        });
        this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        this.setContentPane(mainPanel);
        this.pack();
    }

    public static void main(String[] args) throws Exception {

        JFrame frame = new mainGUI("ZP PROJEKAT UBI ME");
        frame.setSize(800,500);
        frame.setVisible(true);
    }

    private void createUIComponents() {
        // TODO: place custom component creation code here

    }
}
