package com.example.jwt.env.AESUtil;

public class AESUtilEnv {
    private final String SECRET_KEY;
    private final String INIT_VECTOR;

    public AESUtilEnv(){
        this.SECRET_KEY = "ef03e4280591adb37d0844d9ef1e2db4";
        this.INIT_VECTOR = "b07d9ce9bfa38991fc4d467cc638a6c8";
    }

    public String getSECRET_KEY() {
        return SECRET_KEY;
    }
    public String getINIT_VECTOR() {
        return INIT_VECTOR;
    }

}
