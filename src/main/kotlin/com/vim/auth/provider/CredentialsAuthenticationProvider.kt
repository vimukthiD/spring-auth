package com.vim.auth.provider

import com.vim.auth.functional.PasswordMatcher
import com.vim.auth.functional.UserRetrievingFunction
import com.vim.auth.functional.UserStatusQuery
import com.vim.auth.model.JwtUser
import com.vim.auth.model.UserContext.Companion.create
import com.vim.auth.utils.getLogger
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.authentication.*
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Component
import org.springframework.util.Assert
import java.util.stream.Collectors

@Component
class CredentialsAuthenticationProvider<T : JwtUser?> @Autowired constructor(
    private val userRetriever: UserRetrievingFunction<String, T?>,
    private val statusQuery: UserStatusQuery<T>,
    private val passwordMatcherFunction: PasswordMatcher
) : AuthenticationProvider {
    private val logger = getLogger(javaClass)

    @Throws(AuthenticationException::class)
    override fun authenticate(authentication: Authentication): Authentication {
        Assert.notNull(authentication, "No authentication data provided")
        val username = authentication.principal as String
        val password = authentication.credentials as String
        val user = userRetriever.retrieve(username) ?: run {
            logger.error("There was no user found for the userName [{}]", username)
            throw UsernameNotFoundException(
                "User not found: $username"
            )
        }
        if (!passwordMatcherFunction.matches(password, user.password, user.encodedPasswordSalt)) {
            throw BadCredentialsException("Authentication Failed. Username or Password not valid.")
        }
        if (user.roleNames.isEmpty()) {
            throw InsufficientAuthenticationException("User has no roles assigned")
        }
        if (!user.isStatusValid) {
            logger.info("Invalid user status")
            throw LockedException(statusQuery.inquire(user))
        }
        val authorities = user.roleNames.stream()
            .map { role: String? -> SimpleGrantedAuthority(role) }
            .collect(Collectors.toList())
        val userContext = create(user.userName, authorities)
        return UsernamePasswordAuthenticationToken(userContext, null, userContext.authorities)
    }

    override fun supports(authentication: Class<*>): Boolean {
        return UsernamePasswordAuthenticationToken::class.java.isAssignableFrom(authentication)
    }

}