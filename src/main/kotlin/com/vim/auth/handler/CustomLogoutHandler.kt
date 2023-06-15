package com.vim.auth.handler

import com.vim.auth.config.AUTHENTICATION_HEADER_NAME
import com.vim.auth.functional.UserLoginStatusUpdateFunction
import com.vim.auth.jwt.JwtFactory
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.logout.LogoutHandler
import org.springframework.stereotype.Component

@Component
class CustomLogoutHandler(
    private val userLoginStatusUpdateFunction: UserLoginStatusUpdateFunction,
    private val jwtFactory: JwtFactory
) : LogoutHandler {
    override fun logout(request: HttpServletRequest, response: HttpServletResponse, authentication: Authentication) {
        try {
            val authHeader = request.getHeader(AUTHENTICATION_HEADER_NAME)
            val claims = jwtFactory.parseClaimsForToken(jwtFactory.extractTokenString(authHeader)).body
            userLoginStatusUpdateFunction.updateUserStatus(claims.subject, claims.id, false)
        } catch (e: Throwable) {
            e.printStackTrace()
        }
    }
}