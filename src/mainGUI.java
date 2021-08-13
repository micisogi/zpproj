import javax.swing.*;

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

        this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        this.setContentPane(mainPanel);
//        tabbedPane1.addTab("Prvi",new JPanel());
//        tabbedPane1.addTab("Drugi",new JPanel());
        this.pack();
    }

    public static void main(String[] args){
        JFrame frame = new mainGUI("ZP PROJEKAT UBI ME");
        frame.setSize(800,500);
        frame.setVisible(true);
    }

    private void createUIComponents() {
        // TODO: place custom component creation code here

    }
}
