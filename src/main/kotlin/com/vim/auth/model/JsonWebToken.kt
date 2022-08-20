package com.vim.auth.model

import java.time.LocalDateTime

interface JsonWebToken {
    val tokenString: String?
    val roles: List<String?>?
    val dateExpire: LocalDateTime?
}