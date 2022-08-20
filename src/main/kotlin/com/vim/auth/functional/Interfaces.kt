package com.vim.auth.functional

fun interface PasswordMatcher {
    fun matches(rawPassword: CharSequence?, encodedPassword: String?, encodedSalt: String?): Boolean
}

fun interface UserLoginStatusUpdateFunction {
    fun updateUserStatus(subject: String?, tokenId: String?, isLogin: Boolean)
}

fun interface UserRetrievingFunction<I, T> {
    fun retrieve(i: I): T?
}

fun interface UserStatusQuery<T> {
    fun inquire(user: T): String?
}