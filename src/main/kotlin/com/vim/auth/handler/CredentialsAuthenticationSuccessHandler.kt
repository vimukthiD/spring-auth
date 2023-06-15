package com.vim.auth.handler

import com.fasterxml.jackson.databind.ObjectMapper
import com.vim.auth.functional.UserLoginStatusUpdateFunction
import com.vim.auth.jwt.JwtFactory
import com.vim.auth.model.JsonWebToken
import com.vim.auth.model.UserContext
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.core.Authentication
import org.springframework.security.web.WebAttributes
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.stereotype.Component
import java.io.IOException

@Component
class CredentialsAuthenticationSuccessHandler @Autowired constructor(
    private val mapper: ObjectMapper,
    private val tokenFactory: JwtFactory,
    private val userLoginStatusUpdateFunction: UserLoginStatusUpdateFunction?
) : AuthenticationSuccessHandler {
    @Throws(IOException::class)
    override fun onAuthenticationSuccess(
        request: HttpServletRequest, response: HttpServletResponse,
        authentication: Authentication
    ) {
        val userContext = authentication.principal as UserContext
        val accessToken: JsonWebToken = tokenFactory.createAccessToken(userContext)
        userLoginStatusUpdateFunction?.updateUserStatus(userContext.username, userContext.tokenId, true)
        response.status = HttpStatus.OK.value()
        response.contentType = MediaType.APPLICATION_JSON_VALUE
        mapper.writeValue(response.writer, accessToken)
        clearAuthenticationAttributes(request)
    }

    private fun clearAuthenticationAttributes(request: HttpServletRequest) {
        val session = request.getSession(false) ?: return
        session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION)
    }
}