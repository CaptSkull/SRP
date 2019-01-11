package SRP6a;

import java.math.BigInteger;
import java.security.SecureRandom;

public class Client {
    private BigInteger N;
    private BigInteger g;
    private BigInteger k;
    private BigInteger x;
    private BigInteger v;
    private BigInteger a;
    private BigInteger A;
    private BigInteger B;
    private BigInteger u;
    private BigInteger K;
    private BigInteger S;
    private BigInteger M_C;
    private String L;
    private String p;
    private String s;

    public Client(BigInteger N, BigInteger g, BigInteger k, String L, String p) {
        this.N = N;
        this.g = g;
        this.k = k;
        this.L = L;
        this.p = p;
    }
    public void setCredentials() {
        s = Salt();
        x = SHA_256.hash(s, p);
        v = g.modPow(x, N);
    }
    private String Salt() {
        final int size = 10;
        final String ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        final SecureRandom RANDOM = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < size; ++i) {
            sb.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
        }
        return sb.toString();
    }
    public BigInteger gen_A() {
        a = new BigInteger(1024, new SecureRandom());
        A = g.modPow(a, N);
        return A;
    }
    public void sAndB (String s, BigInteger B) {
        this.s = s;
        this.B = B;
    }
    public void gen_u() throws IllegalAccessException {
        u = SHA_256.hash(A, B);
        if (u.equals(BigInteger.ZERO)) //u!=0
            throw new IllegalAccessException();
    }
    public void sessionKey() {
        x = SHA_256.hash(s, p);
        S = (B.subtract(k.multiply(g.modPow(x, N)))).modPow(a.add(u.multiply(x)), N); //(B - K*(g^x mod N))^(a+u*x)) mod N
        K = SHA_256.hash(S);
    }
    public BigInteger genM() {
        M_C = SHA_256.hash(SHA_256.hash(N).xor(SHA_256.hash(g)), SHA_256.hash(L), s, A, B, K); //H(H(N) xor H(g), H(L), s, A, B, K)
        return M_C;
    }

    public boolean compareR(BigInteger R_S) {
        BigInteger R_C = SHA_256.hash(A, M_C, K);
        return R_C.equals(R_S);
    }

    public String get_s() {
        return s;
    }

    public BigInteger get_v() {
        return v;
    }
}
