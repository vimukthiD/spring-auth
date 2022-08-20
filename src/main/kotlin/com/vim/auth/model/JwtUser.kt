package com.vim.auth.model

interface JwtUser {
    var userName: String
    val password: String?
    val encodedPasswordSalt: String?
        get() = ""
    val onlineTokenId: String?
        get() = ""
    var roleNames: MutableList<String>
    val isStatusValid: Boolean
}