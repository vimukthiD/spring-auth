package com.vim.auth.config

import com.fasterxml.jackson.databind.ObjectMapper
import com.vim.auth.RestAuthenticationEntryPoint
import com.vim.auth.filter.CredentialsAuthenticationFilter
import com.vim.auth.filter.JwtAuthenticationFilter
import com.vim.auth.filter.PermittedRequestMatcher
import com.vim.auth.handler.CredentialsAuthenticationFailureHandler
import com.vim.auth.handler.CredentialsAuthenticationSuccessHandler
import com.vim.auth.handler.CustomLogoutHandler
import com.vim.auth.jwt.JwtFactory
import com.vim.auth.model.JwtUser
import com.vim.auth.provider.CredentialsAuthenticationProvider
import com.vim.auth.provider.JwtAuthenticationProvider
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.context.annotation.Bean
import org.springframework.http.HttpStatus
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource


const val AUTHENTICATION_HEADER_NAME = "Authorization"
const val AUTHENTICATION_TOKEN_PREFIX = "Bearer "
const val AUTHENTICATION_URL = "/api/user/login"
const val SIGN_OUT_URL = "/api/user/logout"
const val REFRESH_TOKEN_URL = "/api/user/token"
const val API_ROOT_URL = "/api/**"

abstract class BasicSecurityConfiguration<T : JwtUser?> {
    @Autowired
    @Qualifier("permittedUrls")
    protected lateinit var permittedUrls: MutableList<String>

    @Autowired
    @Qualifier("allowedOrigins")
    protected lateinit var allowedOrigins: List<String>

    @Autowired
    @Qualifier("allowedMethods")
    protected val allowedMethods: List<String>? = null

    @Autowired
    protected val authenticationEntryPoint: RestAuthenticationEntryPoint? = null

    @Autowired
    private lateinit var credentialsAuthenticationSuccessHandler: CredentialsAuthenticationSuccessHandler

    @Autowired
    private lateinit var credentialsAuthenticationFailureHandler: CredentialsAuthenticationFailureHandler

    @Autowired
    private lateinit var objectMapper: ObjectMapper

    @Autowired
    private lateinit var jwtFactory: JwtFactory

    @Autowired
    private val customLogoutHandler: CustomLogoutHandler? = null

    @Throws(Exception::class)
    private fun buildUsernamePasswordFilter(
        authenticationManager: AuthenticationManager,
        loginEntryPoint: String
    ): CredentialsAuthenticationFilter {
        val filter = CredentialsAuthenticationFilter(
            loginEntryPoint,
            credentialsAuthenticationSuccessHandler,
            credentialsAuthenticationFailureHandler,
            objectMapper
        )
        filter.setAuthenticationManager(authenticationManager)
        return filter
    }

    @Throws(Exception::class)
    private fun buildJwtTokenAuthenticationProcessingFilter(
        authenticationManager: AuthenticationManager?,
        pathsToSkip: List<String>,
        pattern: String
    ): JwtAuthenticationFilter {
        val matcher = PermittedRequestMatcher(pathsToSkip, pattern)
        val filter = JwtAuthenticationFilter(credentialsAuthenticationFailureHandler, jwtFactory, matcher)
        filter.setAuthenticationManager(authenticationManager)
        return filter
    }

    @Bean
    @Throws(Exception::class)
    open fun filterChain(
        http: HttpSecurity,
        credentialsAuthenticationProvider: CredentialsAuthenticationProvider<T>,
        jwtAuthenticationProvider: JwtAuthenticationProvider<T>
    ): SecurityFilterChain {
        permittedUrls.addAll(listOf(AUTHENTICATION_URL, REFRESH_TOKEN_URL))

        val authenticationManager = http.getSharedObject(AuthenticationManagerBuilder::class.java)
            .authenticationProvider(credentialsAuthenticationProvider)
            .authenticationProvider(jwtAuthenticationProvider)
            .build()

        http
            .authenticationManager(authenticationManager)
            .csrf().disable()
            .cors(Customizer.withDefaults())
            .exceptionHandling()
            .authenticationEntryPoint(authenticationEntryPoint)
            .and()
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .authorizeRequests()
            .antMatchers(*permittedUrls.toTypedArray())
            .permitAll()
            .and()
            .authorizeRequests()
            .antMatchers(API_ROOT_URL).authenticated()
            .and()
            .logout()
            .logoutRequestMatcher(AntPathRequestMatcher(SIGN_OUT_URL))
            .addLogoutHandler(customLogoutHandler)
            .logoutSuccessHandler(HttpStatusReturningLogoutSuccessHandler(HttpStatus.OK))
            .and()
            .addFilterBefore(
                buildUsernamePasswordFilter(authenticationManager, AUTHENTICATION_URL),
                UsernamePasswordAuthenticationFilter::class.java
            )
            .addFilterBefore(
                buildJwtTokenAuthenticationProcessingFilter(
                    authenticationManager,
                    permittedUrls,
                    API_ROOT_URL
                ), UsernamePasswordAuthenticationFilter::class.java
            )
        configureAdditional(http)
        return http.build()
    }


    @Bean
    open fun corsConfigurationSource(): CorsConfigurationSource {
        val configuration = CorsConfiguration()
        configuration.allowedOrigins = allowedOrigins
        configuration.allowedMethods = allowedMethods
        configuration.allowCredentials = true
        configuration.allowedHeaders = listOf(
            "Content-Type",
            AUTHENTICATION_HEADER_NAME,
            "Accept",
            "Host",
            "Content-Length",
            "Accept-Encoding",
            "Accept-Language",
            "Access-Control-Request-Headers",
            "Access-Control-Request-Method",
            "Connection",
            "Origin",
            "User-Agent",
            "Access-Control-Allow-Origin",
            "Referrer-Policy"
        )
        configuration.exposedHeaders = listOf("x-auth-token")
        val source = UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/**", configuration)
        return source
    }

    /**
     * Used to add additional configurations as required.
     *
     * @param http - HttpSecurity object that needs to be configured
     */
    @Throws(Exception::class)
    protected open fun configureAdditional(http: HttpSecurity?) {
        //override if required
    }

}