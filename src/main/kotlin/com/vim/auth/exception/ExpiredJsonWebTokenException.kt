package com.vim.auth.exception

import org.springframework.security.core.AuthenticationException

class ExpiredJsonWebTokenException(private var token: String?, msg: String?, t: Throwable?) :
    AuthenticationException(msg, t) {

    override fun toString(): String {
        return "ExpiredJsonWebTokenException(token=$token)"
    }
}