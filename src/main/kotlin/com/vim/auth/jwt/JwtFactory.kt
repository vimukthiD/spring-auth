package com.vim.auth.jwt

import com.vim.auth.config.AUTHENTICATION_TOKEN_PREFIX
import com.vim.auth.config.JwtFactoryConfiguration
import com.vim.auth.exception.ExpiredJsonWebTokenException
import com.vim.auth.model.JsonWebToken
import com.vim.auth.model.PortableAccessToken
import com.vim.auth.model.UserContext
import com.vim.auth.utils.getLogger
import com.vim.auth.utils.isValidString
import io.jsonwebtoken.*
import io.jsonwebtoken.security.Keys
import io.jsonwebtoken.security.SecurityException
import lombok.extern.slf4j.Slf4j
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.authentication.AuthenticationServiceException
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.stereotype.Component
import java.time.LocalDateTime
import java.time.ZoneId
import java.util.*
import java.util.stream.Collectors

private const val INVALID_JWT = "Invalid JWT"

private const val EXPIRED_JWT = "JWT is expired"

@Slf4j
@Component
class JwtFactory @Autowired constructor(private val settings: JwtFactoryConfiguration) {
    private val logger = getLogger(javaClass)
    fun createAccessToken(userContext: UserContext): PortableAccessToken {
        require(isValidString(userContext.username)) { "Cannot create JWT Token without username" }
        userContext.authorities
        require(!userContext.authorities.isEmpty()) { "User doesn't have any privileges" }
        val claims = Jwts.claims()
            .setId(userContext.tokenId)
            .setSubject(userContext.username)
        val roles = userContext.authorities.stream().map { obj: Any -> obj.toString() }.collect(Collectors.toList())
        val currentTime = LocalDateTime.now()
        val expiryTime = currentTime.plusMinutes(settings.ttlMinutes)
        logger.info("Token expires at {}.", expiryTime)
        val dateCreated = Date.from(currentTime.atZone(ZoneId.systemDefault()).toInstant())
        val dateExpire = Date.from(expiryTime.atZone(ZoneId.systemDefault()).toInstant())
        val token = AUTHENTICATION_TOKEN_PREFIX + Jwts.builder()
            .setClaims(claims)
            .setIssuer(settings.tokenIssuer)
            .setIssuedAt(dateCreated)
            .setExpiration(dateExpire)
            .signWith(Keys.hmacShaKeyFor(settings.secret.toByteArray()), SignatureAlgorithm.HS512)
            .compact()
        return PortableAccessToken(token, roles, expiryTime)
    }

    fun getTemporaryAccessTokenSubject(token: String?): String {
        return try {
            Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(settings.secret.toByteArray()))
                .build()
                .parseClaimsJws(token).body.subject
        } catch (ex: UnsupportedJwtException) {
            logger.error(INVALID_JWT, ex)
            throw BadCredentialsException(INVALID_JWT, ex)
        } catch (ex: MalformedJwtException) {
            logger.error(INVALID_JWT, ex)
            throw BadCredentialsException(INVALID_JWT, ex)
        } catch (ex: IllegalArgumentException) {
            logger.error(INVALID_JWT, ex)
            throw BadCredentialsException(INVALID_JWT, ex)
        } catch (ex: SecurityException) {
            logger.error(INVALID_JWT, ex)
            throw BadCredentialsException(INVALID_JWT, ex)
        } catch (expiredEx: ExpiredJwtException) {
            logger.info(EXPIRED_JWT, expiredEx)
            throw ExpiredJsonWebTokenException(token, EXPIRED_JWT, expiredEx)
        }
    }

    fun parseClaimsForToken(token: String?): Jws<Claims> {
        return try {
            val tokenString = extractTokenString(token)
            Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(settings.secret.toByteArray()))
                .build().parseClaimsJws(tokenString)
        } catch (ex: UnsupportedJwtException) {
            logger.error(INVALID_JWT, ex)
            throw BadCredentialsException(INVALID_JWT, ex)
        } catch (ex: MalformedJwtException) {
            logger.error(INVALID_JWT, ex)
            throw BadCredentialsException(INVALID_JWT, ex)
        } catch (ex: IllegalArgumentException) {
            logger.error(INVALID_JWT, ex)
            throw BadCredentialsException(INVALID_JWT, ex)
        } catch (ex: SecurityException) {
            logger.error(INVALID_JWT, ex)
            throw BadCredentialsException(INVALID_JWT, ex)
        } catch (expiredEx: ExpiredJwtException) {
            logger.info(EXPIRED_JWT, expiredEx)
            throw ExpiredJsonWebTokenException(token, EXPIRED_JWT, expiredEx)
        }
    }

    fun parseClaimsForToken(token: JsonWebToken): Jws<Claims> {
        return parseClaimsForToken(token.tokenString)
    }

    fun validateAccessToken(accessToken: String?): Boolean {
        return try {
            Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(settings.secret.toByteArray()))
                .build()
                .parseClaimsJws(extractTokenString(accessToken))
            true
        } catch (e: Exception) {
            logger.error("Error occurred while attempting to decrypt the accessToken.", e)
            false
        }
    }

    fun extractTokenString(headerValue: String?): String {
        if (!isValidString(headerValue)) {
            throw AuthenticationServiceException("Authorization header is blank.")
        }
        if (headerValue!!.length < AUTHENTICATION_TOKEN_PREFIX.length) {
            throw AuthenticationServiceException("Invalid authorization header size.")
        }
        return if (headerValue.startsWith(AUTHENTICATION_TOKEN_PREFIX)) {
            headerValue.substring(AUTHENTICATION_TOKEN_PREFIX.length)
        } else headerValue
    }

    fun createTemporaryAuthToken(email: String?): String {
        require(isValidString(email)) { "Cannot create JWT without username" }
        val claims = Jwts.claims().setSubject(email)
        val currentTime = LocalDateTime.now()
        val dateCreated = Date.from(currentTime.atZone(ZoneId.systemDefault()).toInstant())
        val dateExpire =
            Date.from(currentTime.plusMinutes(settings.ttlMinutes).atZone(ZoneId.systemDefault()).toInstant())
        return Jwts.builder()
            .setClaims(claims)
            .setIssuer(settings.tokenIssuer)
            .setIssuedAt(dateCreated)
            .setExpiration(dateExpire)
            .signWith(Keys.hmacShaKeyFor(settings.secret.toByteArray()), SignatureAlgorithm.HS512)
            .compact()
    }
}