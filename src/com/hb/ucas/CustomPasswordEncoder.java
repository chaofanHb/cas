package com.hb.ucas;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.DigestUtils;

public class CustomPasswordEncoder implements PasswordEncoder {
	private static Logger log = LoggerFactory.getLogger(CustomPasswordEncoder.class);

	@Override
	public String encode(CharSequence arg0) {
        try {
            return DigestUtils.md5DigestAsHex(arg0.toString().getBytes());
        } catch (Exception e) {
            return null;
        }
	}

	@Override
	public boolean matches(CharSequence inputPwd, String dbPwd) {
        //通过md5加密后的密码
        String pass = null;
        // 判断密码是否存在
        if (inputPwd == null || (pass = this.encode(inputPwd)) == null) {
            return false;
        }
        //比较密码是否相等的问题
        return pass.equals(dbPwd);
	}

}
