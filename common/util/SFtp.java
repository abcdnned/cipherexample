package cn.insightcredit.cloud.app.loan.common.baidukeys.common.util;

import com.jcraft.jsch.*;
import com.jcraft.jsch.ChannelSftp.LsEntry;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.Vector;

/**
 * SFTP(Secure File Transfer Protocol)，安全文件传送协议。
 */
@Slf4j
public class SFtp {

    public static final int SFTP_DEFAULT_PORT = 22;

    // 字符编码
    private static final String ENCODING_CODE = "UTF-8";
    // 缓冲区大小
    private static final int BUFFER_SIZE = 1024 * 2;
    // 读取数据时间和链接超时时间都设置为30s
    private static final int TIME_OUT = 30 * 1000;
    /**
     * Session
     */
    private Session session = null;
    /**
     * Channel
     */
    private ChannelSftp channel = null;
    /**
     * SFTP服务器IP地址
     */
    private String host;
    /**
     * SFTP服务器端口
     */
    private int port;

    /**
     * 用户名
     */
    private String username;
    /**
     * 密码
     */
    private String password;

    /**
     * SFTP 安全文件传送协议
     *
     * @param host     SFTP服务器IP地址
     * @param port     SFTP服务器端口
     * @param username 用户名
     * @param password 密码
     */
    public SFtp(String host, int port, String username, String password) {
        this.host = host;
        this.port = port;
        this.username = username;
        this.password = password;
    }

    /**
     * 登陆SFTP服务器
     *
     * @return boolean
     */
    public void login() throws JSchException {

        JSch jsch = new JSch();
        if (this.port > 0) {
            session = jsch.getSession(username, host, port);
        } else {
            session = jsch.getSession(username, host);
        }

        if (password != null) {
            session.setPassword(password);
        }
        Properties config = new Properties();
        config.put("StrictHostKeyChecking", "no");
        session.setConfig(config);

        session.setTimeout(TIME_OUT);

        session.connect();

        channel = (ChannelSftp) session.openChannel("sftp");
        channel.connect();

    }

    /**
     * 上传文件
     * <p>
     * 使用示例，SFTP服务器上的目录结构如下：/testA/testA_B/
     * <table border="1">
     * <tr><td>当前目录</td><td>方法</td><td>参数：绝对路径/相对路径</td><td>上传后</td></tr>
     * <tr><td>/</td><td>uploadFile("testA","upload.txt",new FileInputStream(new File("up.txt")))
     * </td><td>相对路径</td><td>/testA/upload.txt</td></tr>
     * <tr><td>/</td><td>uploadFile("testA/testA_B","upload.txt",new FileInputStream(new File("up.txt")))
     * </td><td>相对路径</td><td>/testA/testA_B/upload.txt</td></tr>
     * <tr><td>/</td><td>uploadFile("/testA/testA_B","upload.txt",new FileInputStream(new File("up.txt")))
     * </td><td>绝对路径</td><td>/testA/testA_B/upload.txt</td></tr>
     * </table>
     * </p>
     *
     * @param pathName SFTP服务器目录
     * @param fileName 服务器上保存的文件名
     * @param input    输入文件流
     *
     * @return boolean
     */
    public boolean uploadFile(String pathName, String fileName, InputStream input) throws SftpException {

        String currentDir = currentDir();

        if (StringUtils.isEmpty(currentDir)) {
            return false;
        }

        if (!changeDir(pathName)) {
            return false;
        }

        try {
            channel.put(input, fileName, ChannelSftp.OVERWRITE);
            if (!existFile(fileName)) {
                return false;
            }
            return true;
        } finally {
            changeDir(currentDir);
        }
    }

    /**
     * 上传文件
     * <p>
     * 使用示例，SFTP服务器上的目录结构如下：/testA/testA_B/
     * <table border="1">
     * <tr><td>当前目录</td><td>方法</td><td>参数：绝对路径/相对路径</td><td>上传后</td></tr>
     * <tr><td>/</td><td>uploadFile("testA","upload.txt","up.txt")</td><td>相对路径</td><td>/testA/upload.txt</td></tr>
     * <tr><td>/</td><td>uploadFile("testA/testA_B","upload.txt","up.txt")</td><td>相对路径</td><td>/testA/testA_B/upload
     * .txt</td></tr>
     * <tr><td>/</td><td>uploadFile("/testA/testA_B","upload.txt","up.txt")
     * </td><td>绝对路径</td><td>/testA/testA_B/upload.txt</td></tr>
     * </table>
     * </p>
     *
     * @param pathName  SFTP服务器目录
     * @param fileName  服务器上保存的文件名
     * @param localFile 本地文件
     *
     * @return boolean
     */
    public boolean uploadFile(String pathName, String fileName, String localFile) throws SftpException {

        String currentDir = currentDir();
        if (!changeDir(pathName)) {
            return false;
        }

        try {
            // OVERWIRITE: 如果目标文件已经存在,传输的文件将完全覆盖目标文件,产生新的文件
            channel.put(localFile, fileName, ChannelSftp.OVERWRITE);
            if (!existFile(fileName)) {
                return false;
            }
            return true;

        } finally {
            changeDir(currentDir);
        }
    }

    /**
     * 下载文件
     * <p>
     * 使用示例，SFTP服务器上的目录结构如下：/testA/testA_B/
     * <table border="1">
     * <tr><td>当前目录</td><td>方法</td><td>参数：绝对路径/相对路径</td><td>下载后</td></tr>
     * <tr><td>/</td><td>downloadFile("testA","down.txt","D:\\downDir")</td><td>相对路径</td><td>D:\\downDir\\down
     * .txt</td></tr>
     * <tr><td>/</td><td>downloadFile("testA/testA_B","down.txt","D:\\downDir")
     * </td><td>相对路径</td><td>D:\\downDir\\down.txt</td></tr>
     * <tr><td>/</td><td>downloadFile("/testA/testA_B","down.txt","D:\\downDir")
     * </td><td>绝对路径</td><td>D:\\downDir\\down.txt</td></tr>
     * </table>
     * </p>
     *
     * @param remotePath SFTP服务器目录
     * @param fileName   服务器上需要下载的文件名
     * @param localPath  本地保存路径
     *
     * @return boolean
     */
    public boolean downloadFile(String remotePath, String fileName, String localPath) throws SftpException {

        String currentDir = currentDir();
        if (!changeDir(remotePath)) {
            return false;
        }

        try {
            String localFilePath = localPath + File.separator + fileName;
            channel.get(fileName, localFilePath);

            File localFile = new File(localFilePath);
            if (!localFile.exists()) {
                return false;
            }
            return true;
        } finally {
            changeDir(currentDir);
        }
    }

    /**
     * 切换工作目录
     * <p>
     * 使用示例，SFTP服务器上的目录结构如下：/testA/testA_B/
     * <table border="1">
     * <tr><td>当前目录</td><td>方法</td><td>参数(绝对路径/相对路径)</td><td>切换后的目录</td></tr>
     * <tr><td>/</td><td>changeDir("testA")</td><td>相对路径</td><td>/testA/</td></tr>
     * <tr><td>/</td><td>changeDir("testA/testA_B")</td><td>相对路径</td><td>/testA/testA_B/</td></tr>
     * <tr><td>/</td><td>changeDir("/testA")</td><td>绝对路径</td><td>/testA/</td></tr>
     * <tr><td>/testA/testA_B/</td><td>changeDir("/testA")</td><td>绝对路径</td><td>/testA/</td></tr>
     * </table>
     * </p>
     *
     * @param pathName 路径
     *
     * @return boolean
     */
    public boolean changeDir(String pathName) throws SftpException {
        if (pathName == null || pathName.trim().equals("")) {
            return false;
        }

        channel.cd(pathName.replaceAll("\\\\", "/"));
        return true;
    }

    /**
     * 当前目录下文件名称列表
     *
     * @return String[]
     */
    public String[] lsFiles() throws SftpException {
        return list(Filter.FILE);
    }

    /**
     * 指定目录下文件名称列表
     *
     * @return String[]
     */
    public String[] lsFiles(String pathName) throws SftpException {
        String currentDir = currentDir();
        if (!changeDir(pathName)) {
            return new String[0];
        }
        ;
        String[] result = list(Filter.FILE);
        if (!changeDir(currentDir)) {
            return new String[0];
        }
        return result;
    }

    /**
     * 当前目录是否存在文件
     *
     * @param name 文件名
     *
     * @return boolean
     */
    public boolean existFile(String name) throws SftpException {
        return exist(lsFiles(), name);
    }

    /**
     * 指定目录下，是否存在文件
     *
     * @param path 目录
     * @param name 文件名
     *
     * @return boolean
     */
    public boolean existFile(String path, String name) throws SftpException {
        return exist(lsFiles(path), name);
    }

    /**
     * 当前工作目录
     *
     * @return String
     */
    public String currentDir() throws SftpException {
        return channel.pwd();
    }

    /**
     * 删除文件
     *
     * @param fileName 文件名
     *
     * @return boolean
     */
    public boolean delFile(String filePath, String fileName) throws SftpException {
        if (StringUtils.isEmpty(filePath) || StringUtils.isEmpty(fileName)) {
            return false;
        }

        if (!existFile(filePath, fileName)) {
            return true;
        }
        channel.rm(filePath + "/" + fileName);
        return true;

    }

    /**
     * 删除文件
     *
     * @param fileName 文件名
     *
     * @return boolean
     */
    public boolean delFile(String fileName) throws SftpException {
        if (fileName == null || fileName.trim().equals("")) {
            return false;
        }

        if (!existFile(fileName)) {
            return true;
        }
        channel.rm(fileName);
        return true;

    }

    /**
     * 登出
     */
    public void logout() {
        if (channel != null) {
            channel.quit();
            channel.disconnect();
        }
        if (session != null) {
            session.disconnect();
        }
    }

    /**
     * 列出当前目录下的文件及文件夹
     *
     * @param filter 过滤参数
     *
     * @return String[]
     */
    @SuppressWarnings("unchecked")
    private String[] list(Filter filter) throws SftpException {
        Vector<LsEntry> list = null;
        // ls方法会返回两个特殊的目录，当前目录(.)和父目录(..)
        list = channel.ls(channel.pwd());

        List<String> resultList = new ArrayList<String>();
        for (LsEntry entry : list) {
            if (filter(entry, filter)) {
                resultList.add(entry.getFilename());
            }
        }
        return resultList.toArray(new String[0]);
    }

    ;

    /**
     * 判断是否是否过滤条件
     *
     * @param entry LsEntry
     * @param f     过滤参数
     *
     * @return boolean
     */
    private boolean filter(LsEntry entry, Filter f) {
        if (f.equals(Filter.ALL)) {
            return !entry.getFilename().equals(".") && !entry.getFilename().equals("..");
        } else if (f.equals(Filter.FILE)) {
            return !entry.getFilename().equals(".") && !entry.getFilename().equals("..") && !entry.getAttrs().isDir();
        } else if (f.equals(Filter.DIR)) {
            return !entry.getFilename().equals(".") && !entry.getFilename().equals("..") && entry.getAttrs().isDir();
        }
        return false;
    }

    /**
     * 根目录
     *
     * @return String
     */
    private String homeDir() {
        try {
            return channel.getHome();
        } catch (SftpException e) {
            return "/";
        }
    }

    /**
     * 判断字符串是否存在于数组中
     *
     * @param strArr 字符串数组
     * @param str    字符串
     *
     * @return boolean
     */
    private boolean exist(String[] strArr, String str) {
        if (strArr == null || strArr.length == 0) {
            return false;
        }
        if (str == null || str.trim().equals("")) {
            return false;
        }
        for (String s : strArr) {
            if (s.equalsIgnoreCase(str)) {
                return true;
            }
        }
        return false;
    }

    public void createIfNotExist(String dir) {

        try {
            channel.cd(dir);
        } catch (SftpException e) {
            try {
                channel.mkdir(dir);
            } catch (SftpException ee) {
                log.error("error:{} ",ee);
            }

        }
    }

    /**
     * 枚举，用于过滤文件和文件夹
     */
    private enum Filter {
        /**
         * 文件及文件夹
         */ALL, /**
         * 文件
         */FILE, /**
         * 文件夹
         */DIR
    }

}