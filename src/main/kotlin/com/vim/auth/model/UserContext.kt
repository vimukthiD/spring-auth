package com.vim.auth.model

import com.vim.auth.utils.generateId
import com.vim.auth.utils.isValidString
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import java.io.Serializable


class UserContext : Serializable, UserDetails {
    private val username: String
    private val authorities: List<GrantedAuthority>
    private var password: String? = null
    private var expired = false
    private var locked = false
    private var enabled = false
    private var credentialsExpired = false
    var tokenId: String
        private set

    private constructor(username: String, authorities: List<GrantedAuthority>) {
        this.username = username
        this.authorities = authorities
        tokenId = generateId()
    }

    private constructor(username: String, authorities: List<GrantedAuthority>, onlineTokenId: String) {
        this.username = username
        this.authorities = authorities
        tokenId = onlineTokenId
    }

    fun password(password: String?): UserContext {
        this.password = password
        return this
    }

    fun expired(expired: Boolean): UserContext {
        this.expired = expired
        return this
    }

    fun locked(locked: Boolean): UserContext {
        this.locked = locked
        return this
    }

    fun enabled(enabled: Boolean): UserContext {
        this.enabled = enabled
        return this
    }

    fun credentialsExpired(credentialsExpired: Boolean): UserContext {
        this.credentialsExpired = credentialsExpired
        return this
    }

    override fun getAuthorities(): MutableCollection<out GrantedAuthority> {
        return authorities.toMutableList()
    }

    override fun getPassword(): String {
        return password!!
    }

    override fun getUsername(): String {
        return username
    }

    override fun isAccountNonExpired(): Boolean {
        return expired
    }

    override fun isAccountNonLocked(): Boolean {
        return locked
    }

    override fun isCredentialsNonExpired(): Boolean {
        return credentialsExpired
    }

    override fun isEnabled(): Boolean {
        return enabled
    }

    companion object {
        @JvmStatic
        @JvmOverloads
        fun create(
            username: String,
            authorities: List<GrantedAuthority>,
            onlineTokenId: String = generateId()
        ): UserContext {
            require(isValidString(username)) { "Username is blank: $username" }
            return UserContext(username, authorities, onlineTokenId)
        }
    }
}