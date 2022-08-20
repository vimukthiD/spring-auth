package com.vim.auth.model

import com.fasterxml.jackson.annotation.JsonFormat
import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import com.fasterxml.jackson.databind.annotation.JsonSerialize
import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateTimeDeserializer
import com.fasterxml.jackson.datatype.jsr310.ser.LocalDateTimeSerializer
import java.io.Serializable
import java.time.LocalDateTime

class PortableAccessToken(
    override val tokenString: String, override val roles: List<String>, @field:JsonFormat(
        shape = JsonFormat.Shape.STRING, pattern = "dd-MM-yyyy HH:mm:ss"
    ) @field:JsonSerialize(using = LocalDateTimeSerializer::class) @field:JsonDeserialize(
        using = LocalDateTimeDeserializer::class
    ) override val dateExpire: LocalDateTime
) : JsonWebToken, Serializable