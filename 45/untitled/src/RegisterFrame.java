import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.awt.Desktop;
import java.net.URI;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class RegisterFrame extends JFrame {
    private JTextField usernameField;  // 用户名输入框
    private JPasswordField passwordField;  // 密码输入框
    private JButton registerButton;  // 注册按钮
    private JButton loginButton;  // 登录按钮
    private JButton chooseFileButton;  // 选择文件按钮
    private JLabel filePathLabel;  // 显示文件路径的标签
    private JLabel statusLabel;  // 状态标签

    private static final String SECRET_KEY = "1234567890123456"; // 16字符的密钥 (128-bit)
    private static final String EXE_FILE_PATH = "path_to_your_exe_file.exe";  // EXE文件的路径
    private static final String IP_ADDRESS = "192.168.1.100";  // 程序内设置的IP地址

    // 构造函数
    public RegisterFrame() {
        setTitle("少女的末路");
        setSize(400, 350);  // 设置窗口大小
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);  // 关闭窗口时不退出程序
        setLocationRelativeTo(null);  // 窗口居中显示

        // 创建一个自定义的面板，用于显示背景
        BackgroundPanel backgroundPanel = new BackgroundPanel();
        backgroundPanel.setLayout(null);  // 使用绝对布局

        // 用户名标签
        JLabel usernameLabel = new JLabel("账号:");
        usernameLabel.setBounds(50, 60, 60, 30);  // 设置标签位置
        backgroundPanel.add(usernameLabel);

        // 用户名输入框
        usernameField = new JTextField();
        usernameField.setBounds(120, 60, 160, 30);  // 设置输入框位置
        backgroundPanel.add(usernameField);

        // 密码标签
        JLabel passwordLabel = new JLabel("密码:");
        passwordLabel.setBounds(50, 100, 60, 30);  // 设置标签位置
        backgroundPanel.add(passwordLabel);

        // 密码输入框
        passwordField = new JPasswordField();
        passwordField.setBounds(120, 100, 160, 30);  // 设置输入框位置
        backgroundPanel.add(passwordField);

        // 注册按钮
        registerButton = new JButton("注册");
        registerButton.setBounds(120, 140, 75, 30);  // 设置按钮位置
        backgroundPanel.add(registerButton);

        // 登录按钮
        loginButton = new JButton("登录");
        loginButton.setBounds(200, 140, 75, 30);  // 设置登录按钮位置
        backgroundPanel.add(loginButton);

        // 选择文件按钮
        chooseFileButton = new JButton("选择文件");
        chooseFileButton.setBounds(120, 180, 150, 30);  // 设置按钮位置
        backgroundPanel.add(chooseFileButton);

        // 显示文件路径的标签
        filePathLabel = new JLabel("文件路径: ");
        filePathLabel.setBounds(50, 250, 300, 30);
        backgroundPanel.add(filePathLabel);

        // 状态标签，用于显示注册成功或失败的消息
        statusLabel = new JLabel("");
        statusLabel.setBounds(120, 280, 200, 30);  // 设置标签位置
        backgroundPanel.add(statusLabel);

        // 注册按钮点击事件
        registerButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                String username = usernameField.getText();
                String password = new String(passwordField.getPassword());
                // 调用注册方法
                register(username, password);
                statusLabel.setText("注册成功！");
                generateAutoexecFile();  // 生成autoexec.cfg文件
            }
        });

        // 登录按钮点击事件
        loginButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                String username = usernameField.getText();
                String password = new String(passwordField.getPassword());
                // 调用登录方法
                login(username, password);
            }
        });

        // 选择文件按钮点击事件
        chooseFileButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                chooseFile();  // 打开文件选择窗口
            }
        });

        // 将自定义的背景面板添加到窗口中
        add(backgroundPanel);
    }

    // 注册功能
    private void register(String username, String password) {
        String encryptedPassword = encrypt(password);  // 对密码进行加密
        saveAccountData(username, encryptedPassword);  // 将用户名和加密后的密码保存到文件
    }

    // 登录功能
    private void login(String username, String password) {
        String encryptedPassword = encrypt(password);  // 加密用户输入的密码
        String storedPassword = getStoredPassword(username);  // 获取存储的密码

        if (encryptedPassword != null && encryptedPassword.equals(storedPassword)) {
            statusLabel.setText("登录成功！");
            launchExeFile();  // 启动EXE文件
            connectToSteamServer();  // 成功登录后连接到Steam服务器
        } else {
            statusLabel.setText("登录失败！");
        }
    }

    // 从文件中获取存储的密码
    private String getStoredPassword(String username) {
        try (BufferedReader reader = new BufferedReader(new FileReader("account.txt"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] accountData = line.split(",");
                if (accountData[0].equals(username)) {
                    return accountData[1];  // 返回加密后的密码
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;  // 如果没有找到用户名，返回null
    }

    // 将用户名和加密后的密码保存到文件
    private void saveAccountData(String username, String encryptedPassword) {
        try (FileWriter writer = new FileWriter("account.txt", true)) {  // 使用FileWriter来写入文件
            writer.write(username + "," + encryptedPassword + "\n");  // 格式：用户名,加密后的密码
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // 加密密码
    private String encrypt(String password) {
        try {
            // 使用AES加密算法和密钥
            SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);  // 初始化为加密模式
            byte[] encrypted = cipher.doFinal(password.getBytes());  // 执行加密
            return Base64.getEncoder().encodeToString(encrypted);  // 将加密后的字节转换为Base64字符串
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    // 打开文件选择窗口
    private void chooseFile() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("选择文件夹");
        fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY); // 设置只能选择文件夹
        int result = fileChooser.showOpenDialog(this);

        if (result == JFileChooser.APPROVE_OPTION) {
            // 获取选择的文件夹路径
            File selectedFolder = fileChooser.getSelectedFile();
            filePathLabel.setText("文件路径: " + selectedFolder.getAbsolutePath());  // 显示文件夹路径
        }
    }

    // 生成autoexec.cfg文件并保存账户信息和快捷键绑定
    private void generateAutoexecFile() {
        String username = usernameField.getText();
        String password = new String(passwordField.getPassword());

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("选择文件夹");
        fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);  // 只能选择文件夹
        int result = fileChooser.showOpenDialog(this);

        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFolder = fileChooser.getSelectedFile();
            File autoexecFile = new File(selectedFolder, "autoexec.cfg");

            try (BufferedWriter writer = new BufferedWriter(new FileWriter(autoexecFile))) {
                // 写入账户信息
                writer.write("setinfo unitedrpg\n\n");

                // 快捷键绑定
                writer.write("//快捷键绑定\n");
                writer.write("bind b \"sm_rpg\"\n");
                writer.write("bind n \"sm_wanjia\"\n");
                writer.write("bind o \"sm_vipfree\"\n");
                writer.write("bind p \"sm_vipvote\"\n");
                writer.write("bind m \"viewskill\"\n");
                writer.write("bind k \"sm_myitem\"\n");

                // 保存用户名和密码
                writer.write("\n// 账户信息\n");
                writer.write("username=" + username + "\n");
                writer.write("password=" + password + "\n");

                statusLabel.setText("autoexec.cfg文件已生成！");
            } catch (IOException e) {
                e.printStackTrace();
                statusLabel.setText("生成文件失败！");
            }
        }
    }

    // 启动EXE文件并自动连接到指定IP地址
    private void launchExeFile() {
        try {
            // 构造命令，启动exe文件并传递IP地址作为参数
            String command = EXE_FILE_PATH + " " + IP_ADDRESS;  // 假设exe文件可以接受IP地址作为参数
            Process process = Runtime.getRuntime().exec(command);  // 启动exe文件
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // 自动连接到Steam服务器
    private void connectToSteamServer() {
        try {
            String steamUrl = "steam://connect/220.231.144.94:27015/rungameid/550";  // Steam链接
            URI uri = new URI(steamUrl);  // 创建URI
            Desktop desktop = Desktop.getDesktop();  // 获取桌面对象
            desktop.browse(uri);  // 打开Steam链接
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 自定义的背景面板
    private class BackgroundPanel extends JPanel {
        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);  // 调用父类的paintComponent方法
            ImageIcon backgroundIcon = new ImageIcon("src/background.jpg");  // 这里的路径要改为你的图片路径
            Image backgroundImage = backgroundIcon.getImage();
            g.drawImage(backgroundImage, 0, 0, getWidth(), getHeight(), this);  // 绘制背景图
        }
    }

    // 程序的入口
    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                new RegisterFrame().setVisible(true);  // 显示注册窗口
            }
        });
    }
}
