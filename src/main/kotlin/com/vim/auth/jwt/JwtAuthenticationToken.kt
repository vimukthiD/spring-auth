package com.vim.auth.jwt

import com.vim.auth.model.UserContext
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.GrantedAuthority

class JwtAuthenticationToken : AbstractAuthenticationToken {
    private var accessToken: String = ""
    private var userContext: UserContext? = null

    constructor(unsafeToken: String) : super(emptyList<GrantedAuthority>()) {
        accessToken = unsafeToken
    }

    constructor(userContext: UserContext?, authorities: Collection<GrantedAuthority?>?) : super(authorities) {
        eraseCredentials()
        this.userContext = userContext
        super.setAuthenticated(true)
    }

    override fun setAuthenticated(authenticated: Boolean) {
        require(!authenticated) { "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead" }
        super.setAuthenticated(false)
    }

    override fun getCredentials(): Any {
        return accessToken
    }

    override fun getPrincipal(): Any? {
        return userContext
    }

    override fun eraseCredentials() {
        super.eraseCredentials()
        accessToken = ""
    }

    override fun getName(): String {
        return userContext!!.username
    }
}