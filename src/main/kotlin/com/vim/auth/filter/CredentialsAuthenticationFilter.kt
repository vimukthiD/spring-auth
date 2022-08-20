package com.vim.auth.filter

import com.fasterxml.jackson.databind.ObjectMapper
import com.vim.auth.exception.AuthMethodNotSupportedException
import com.vim.auth.model.LoginRequest
import lombok.extern.slf4j.Slf4j
import org.springframework.http.HttpMethod
import org.springframework.security.authentication.AuthenticationServiceException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import java.io.IOException
import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Slf4j
class CredentialsAuthenticationFilter(
    defaultProcessUrl: String?,
    private val successHandler: AuthenticationSuccessHandler,
    private val failureHandler: AuthenticationFailureHandler,
    private val objectMapper: ObjectMapper
) : AbstractAuthenticationProcessingFilter(defaultProcessUrl) {
    @Throws(IOException::class)
    override fun attemptAuthentication(request: HttpServletRequest, response: HttpServletResponse): Authentication {
        if (HttpMethod.POST.name != request.method) {
            logger.debug("Authentication method not supported. Request method: " + request.method)
            throw AuthMethodNotSupportedException("Authentication method not supported")
        }
        val loginRequest = objectMapper.readValue(request.reader, LoginRequest::class.java)
        if (!loginRequest.isRequestValid()) {
            throw AuthenticationServiceException("Username or Password not provided")
        }
        val token = UsernamePasswordAuthenticationToken(
            loginRequest.userName, loginRequest.password
        )
        return authenticationManager.authenticate(token)
    }

    @Throws(IOException::class, ServletException::class)
    override fun successfulAuthentication(
        request: HttpServletRequest, response: HttpServletResponse, chain: FilterChain,
        authResult: Authentication
    ) {
        successHandler.onAuthenticationSuccess(request, response, authResult)
    }

    @Throws(IOException::class, ServletException::class)
    override fun unsuccessfulAuthentication(
        request: HttpServletRequest, response: HttpServletResponse,
        failed: AuthenticationException
    ) {
        SecurityContextHolder.clearContext()
        failureHandler.onAuthenticationFailure(request, response, failed)
    }

    override fun getSuccessHandler(): AuthenticationSuccessHandler {
        return this.successHandler
    }

    override fun getFailureHandler(): AuthenticationFailureHandler {
        return this.failureHandler
    }
}