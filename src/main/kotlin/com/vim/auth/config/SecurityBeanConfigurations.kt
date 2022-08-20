package com.vim.auth.config

import com.vim.auth.functional.PasswordMatcher
import com.vim.auth.functional.UserLoginStatusUpdateFunction
import com.vim.auth.functional.UserRetrievingFunction
import com.vim.auth.functional.UserStatusQuery
import com.vim.auth.model.JwtUser
import com.vim.auth.utils.getLogger
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary

@Configuration
interface SecurityBeanConfigurations<T : JwtUser> {
    @Bean
    @Primary
    fun userRetrievingFunction(): UserRetrievingFunction<String, T?>

    @Bean
    @Primary
    fun userStatusQuery(): UserStatusQuery<T>

    @Bean
    @Primary
    fun passwordMatcherFunction(): PasswordMatcher?

    /**
     * This function is used to update the current logged in token on the client side.
     * This will be used to enable single login and to invalidate old tokens.
     */
    @Bean
    @Primary
    fun userLoginStatusUpdateFunction(): UserLoginStatusUpdateFunction? {
        return UserLoginStatusUpdateFunction { subject: String?, tokenId: String?, isLogin: Boolean ->
            run {
                getLogger(javaClass).trace(
                    "Got params for login status update. subject : [{}], tokenId : [{}], isLogin : [{}]",
                    subject,
                    tokenId,
                    isLogin
                )
            }
        }
    }
}