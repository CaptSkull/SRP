package SRP6a;

import javax.naming.InvalidNameException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

public class Server {
    private BigInteger N;
    private BigInteger g;
    private BigInteger k;
    private BigInteger v;
    private BigInteger A;
    private BigInteger b;
    private BigInteger B;
    private BigInteger u;
    private BigInteger K;
    private String L;
    private String s;
    private Map<String, Pair<String, BigInteger>> database = new HashMap<>();

    public Server(BigInteger N, BigInteger g, BigInteger k) {
        this.N = N;
        this.g = g;
        this.k = k;
    }

    public void setCredentials(String L, String s, BigInteger v) throws InvalidNameException {
        if (!database.containsKey(L)) {
            database.put(L, new Pair<>(s, v));
        } else
            throw new InvalidNameException();
    }

    public void set_A(BigInteger A) throws IllegalAccessException {
        if (A.equals(BigInteger.ZERO)) // A != 0
            throw new IllegalAccessException();
        else
            this.A = A;
    }

    public BigInteger gen_B() {
        b = new BigInteger(1024, new SecureRandom());
        B = (k.multiply(v).add(g.modPow(b, N))).mod(N); //(k*v + g^b mod N) mod N
        return B;
    }

    public void gen_u() throws IllegalAccessException {
        u = SHA_256.hash(A, B);
        if (u.equals(BigInteger.ZERO)) // u != 0
            throw new IllegalAccessException();
    }

    public String getClient_s(String L) throws IllegalAccessException {
        if (database.containsKey(L)) {
            this.L = L;
            s = database.get(this.L).first;
            v = database.get(this.L).second;
            return s;
        } else
            throw new IllegalAccessException();
    }

    public void genSessionKey() {
        BigInteger S = A.multiply(v.modPow(u, N)).modPow(b, N); // (A*(v^u mod N))^b mod N
        K = SHA_256.hash(S);
    }

    public BigInteger test_M(BigInteger M_C) {
        BigInteger M_S = SHA_256.hash(SHA_256.hash(N).xor(SHA_256.hash(g)), SHA_256.hash(L), s, A, B, K); // H(H(N) xor H(g), H(I), s, A, B, K)
        if (M_S.equals(M_C))
            return SHA_256.hash(A, M_S, K); // R = H(A, M, K)
        else
            return BigInteger.ZERO;
    }

    private class Pair<A, B> {
        A first;
        B second;

        Pair(A first, B second) {
            this.first = first;
            this.second = second;
        }
    }
}


