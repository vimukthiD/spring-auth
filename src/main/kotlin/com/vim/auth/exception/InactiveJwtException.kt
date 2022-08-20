package com.vim.auth.exception

import org.springframework.security.core.AuthenticationException

class InactiveJwtException(private var token: String?, msg: String?) : AuthenticationException(msg) {
    override fun toString(): String {
        return "InactiveJwtException(token=$token, msg=${super.message})"
    }
}