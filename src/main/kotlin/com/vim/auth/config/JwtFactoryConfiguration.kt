package com.vim.auth.config

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Configuration

@Configuration
@ConfigurationProperties(prefix = "security.jwt")
class JwtFactoryConfiguration {
    lateinit var secret: String
    var ttlMinutes: Long = 0
    lateinit var tokenIssuer: String
}