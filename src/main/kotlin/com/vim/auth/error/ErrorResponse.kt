package com.vim.auth.error

import org.springframework.http.HttpStatus
import java.util.*

class ErrorResponse constructor(
    private val message: String,
    private val errorCode: ErrorCode,
    private val status: HttpStatus
) {
    private val timestamp: Date = Date()

    override fun toString(): String {
        return "ErrorResponse(message='$message', errorCode=$errorCode, status=$status, timestamp=$timestamp)"
    }

    enum class ErrorCode {
        AUTHENTICATION, JWT_TOKEN_EXPIRED;
    }

    companion object {
        @JvmStatic
        fun of(message: String, errorCode: ErrorCode, status: HttpStatus): ErrorResponse {
            return ErrorResponse(message, errorCode, status)
        }
    }


}