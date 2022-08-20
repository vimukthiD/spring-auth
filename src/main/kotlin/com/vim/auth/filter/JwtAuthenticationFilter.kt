package com.vim.auth.filter

import com.vim.auth.config.AUTHENTICATION_HEADER_NAME
import com.vim.auth.jwt.JwtAuthenticationToken
import com.vim.auth.jwt.JwtFactory
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.util.matcher.RequestMatcher
import java.io.IOException
import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class JwtAuthenticationFilter(
    private val failureHandler: AuthenticationFailureHandler,
    private val jwtFactory: JwtFactory,
    matcher: RequestMatcher?
) : AbstractAuthenticationProcessingFilter(matcher) {
    override fun attemptAuthentication(request: HttpServletRequest, response: HttpServletResponse): Authentication {
        val authHeader = request.getHeader(AUTHENTICATION_HEADER_NAME)
        val tokenString = jwtFactory.extractTokenString(authHeader)
        return authenticationManager.authenticate(JwtAuthenticationToken(tokenString))
    }

    @Throws(IOException::class, ServletException::class)
    override fun successfulAuthentication(
        request: HttpServletRequest, response: HttpServletResponse, chain: FilterChain,
        authResult: Authentication
    ) {
        val context = SecurityContextHolder.createEmptyContext()
        context.authentication = authResult
        SecurityContextHolder.setContext(context)
        chain.doFilter(request, response)
    }

    @Throws(IOException::class, ServletException::class)
    override fun unsuccessfulAuthentication(
        request: HttpServletRequest, response: HttpServletResponse,
        failed: AuthenticationException
    ) {
        SecurityContextHolder.clearContext()
        failureHandler.onAuthenticationFailure(request, response, failed)
    }

    override fun getFailureHandler(): AuthenticationFailureHandler {
        return this.failureHandler
    }
}