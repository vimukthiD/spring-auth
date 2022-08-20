package com.vim.auth.exception

import org.springframework.security.authentication.AuthenticationServiceException

class AuthMethodNotSupportedException(msg: String?) : AuthenticationServiceException(msg)