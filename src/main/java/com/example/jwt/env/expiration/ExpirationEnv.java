package com.example.jwt.env.expiration;

public class ExpirationEnv {
    private final int ACCESS_TOKEN;
    private final int ACCESS_TOKEN_COOKIE;
    private final long REFRESH_TOKEN;
    private final int REFRESH_TOKEN_COOKIE;


    public ExpirationEnv() {
        this.ACCESS_TOKEN = 1000 * 30 * 60; // 30분
        this.REFRESH_TOKEN = 1000L * 60 * 60 * 24 * 14;

        this.ACCESS_TOKEN_COOKIE = 30 * 60;
        this.REFRESH_TOKEN_COOKIE = 14 * 24 * 60 * 60;
    }

    public int getACCESS_TOKEN() { return ACCESS_TOKEN; }
    public long getREFRESH_TOKEN() { return REFRESH_TOKEN; }
    public int getACCESS_TOKEN_COOKIE() { return ACCESS_TOKEN_COOKIE; }
    public int getREFRESH_TOKEN_COOKIE() { return REFRESH_TOKEN_COOKIE; }
}
