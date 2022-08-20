package com.vim.auth.model

import com.vim.auth.utils.isValidString
import java.io.Serializable

class LoginRequest : Serializable {
     val userName: String? = null
     val password: String? = null

    fun isRequestValid() :Boolean {
        return isValidString(userName,password)
    }
}