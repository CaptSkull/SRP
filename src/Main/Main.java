package Main;
import SRP6a.*;
import javax.naming.InvalidNameException;
import java.math.BigInteger;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        String Nhex = "00:f5:0a:08:ad:ff:22:47:58:12:37:db:d3:e8:fc:" +
                "84:4a:f9:50:fb:7c:34:fc:c1:73:29:fa:15:e1:ee:" +
                "15:ae:a9:3f:bb:23:bb:d3:88:22:cc:44:cb:a3:28:" +
                "dc:db:19:b2:fa:b3:72:f9:f9:8a:05:f7:16:4a:39:" +
                "90:19:d4:ee:ae:cd:c7:38:ee:19:22:61:0f:00:91:" +
                "6b:0c:23:18:e5:05:fb:7d:34:4d:fe:22:7e:92:59:" +
                "3d:6f:c1:91:d0:1f:37:b8:41:65:2f:76:54:8f:ab:" +
                "e0:19:93:b3:a6:13:c8:c3:50:2a:5d:13:52:61:8c:" +
                "6c:e2:90:14:41:66:8b:61:5b";
        BigInteger N = new BigInteger(Nhex.replace(":", ""), 16);
        BigInteger g = BigInteger.valueOf(2);
        BigInteger k = SHA_256.hash(N,g);
        Server server = new Server(N,g,k);

        while(true){
            System.out.println("Registration or Authorization ?");
            Scanner input = new Scanner(System.in);
            String menu = input.nextLine();
            switch (menu) {
                case "Registration" : {
                    System.out.println("Login: ");
                    String login = input.next();
                    System.out.println("Password: ");
                    String password = input.next();

                    Client client = new Client(N, g, k, login, password);
                    client.setCredentials();
                    String s = client.get_s();
                    BigInteger v = client.get_v();
                    try {
                        server.setCredentials(login, s, v);
                    } catch (InvalidNameException e) {
                        System.out.println("Username is unavailable");
                    }
                    break;
                }
                case "Authorization" : {
                    System.out.println("Login: ");
                    String login = input.next();

                    System.out.println("Password: ");
                    String password = input.next();

                    Client client = new Client(N, g, k, login, password);

                    BigInteger A = client.gen_A();
                    try {
                        server.set_A(A);
                    } catch (IllegalAccessException e) {
                        System.out.println("Error, A can't be 0");
                        break;
                    }

                    try {
                        String s = server.getClient_s(login);
                        BigInteger B = server.gen_B();
                        client.sAndB(s, B);
                    } catch (IllegalAccessException e) {
                        System.out.println("Unknown username");
                        break;
                    }

                    try {
                        client.gen_u();
                        server.gen_u();
                    } catch (IllegalAccessException e) {
                        System.out.println("Error, u can't be 0");
                        break;
                    }

                    client.sessionKey();
                    server.genSessionKey();
                    BigInteger serverR = server.test_M(client.genM());
                    if (client.compareR(serverR))
                        System.out.println("Welcome dear friend");
                    else
                        System.out.println("Incorrect password!!!");
                    break;
                }
                default:
                    return;
            }
        }
    }
}
