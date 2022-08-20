package com.vim.auth.provider

import com.vim.auth.exception.InactiveJwtException
import com.vim.auth.functional.UserRetrievingFunction
import com.vim.auth.jwt.JwtAuthenticationToken
import com.vim.auth.jwt.JwtFactory
import com.vim.auth.model.JwtUser
import com.vim.auth.model.UserContext.Companion.create
import com.vim.auth.utils.getLogger
import com.vim.auth.utils.isValidString
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Component

@Component
class JwtAuthenticationProvider<T : JwtUser?> @Autowired constructor(
    private val jwtFactory: JwtFactory,
    private val userRetrievingFunction: UserRetrievingFunction<String, T?>
) : AuthenticationProvider {
    private val logger = getLogger(javaClass)

    override fun authenticate(authentication: Authentication): Authentication {
        val accessToken = authentication.credentials as String
        val claims = jwtFactory.parseClaimsForToken(accessToken).body
        val subject = claims.subject
        val retrievedUser = userRetrievingFunction.retrieve(subject) ?: run {
            throw UsernameNotFoundException("No user was found for the name in the token")
        }
        if (isValidString(retrievedUser.onlineTokenId)
            && retrievedUser.onlineTokenId != claims.id
        ) {
            logger.error("The token is not active.")
            throw InactiveJwtException(accessToken, "The Token Is Not Active. User might've logged out")
        }
        val authorities: MutableList<GrantedAuthority> = ArrayList()
        for (roleName in retrievedUser.roleNames) {
            authorities.add(SimpleGrantedAuthority(roleName))
        }
        val context = create(subject, authorities, claims.id)
        return JwtAuthenticationToken(context, context.authorities)
    }

    override fun supports(authentication: Class<*>): Boolean {
        return JwtAuthenticationToken::class.java.isAssignableFrom(authentication)
    }
}