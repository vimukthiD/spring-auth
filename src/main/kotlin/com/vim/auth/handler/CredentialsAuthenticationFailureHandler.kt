package com.vim.auth.handler

import com.fasterxml.jackson.databind.ObjectMapper
import com.vim.auth.error.ErrorResponse
import com.vim.auth.exception.AuthMethodNotSupportedException
import com.vim.auth.exception.ExpiredJsonWebTokenException
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.LockedException
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.stereotype.Component
import java.io.IOException
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse

@Component
class CredentialsAuthenticationFailureHandler @Autowired constructor(private val mapper: ObjectMapper) :
    AuthenticationFailureHandler {
    @Throws(IOException::class)
    override fun onAuthenticationFailure(
        request: HttpServletRequest, response: HttpServletResponse,
        e: AuthenticationException
    ) {
        response.status = HttpStatus.UNAUTHORIZED.value()
        response.contentType = MediaType.APPLICATION_JSON_VALUE
        when (e) {
            is BadCredentialsException -> {
                mapper.writeValue(
                    response.writer,
                    ErrorResponse.of(
                        "Invalid username and/or password!",
                        ErrorResponse.ErrorCode.AUTHENTICATION,
                        HttpStatus.UNAUTHORIZED
                    )
                )
            }

            is ExpiredJsonWebTokenException -> {
                mapper.writeValue(
                    response.writer,
                    ErrorResponse.of(
                        "Token has expired!",
                        ErrorResponse.ErrorCode.JWT_TOKEN_EXPIRED,
                        HttpStatus.UNAUTHORIZED
                    )
                )
            }

            is AuthMethodNotSupportedException, is LockedException -> {
                mapper.writeValue(
                    response.writer,
                    ErrorResponse.of(e.message ?: "", ErrorResponse.ErrorCode.AUTHENTICATION, HttpStatus.UNAUTHORIZED)
                )
            }
        }
        mapper.writeValue(
            response.writer,
            ErrorResponse.of("Authentication failed", ErrorResponse.ErrorCode.AUTHENTICATION, HttpStatus.UNAUTHORIZED)
        )
    }
}