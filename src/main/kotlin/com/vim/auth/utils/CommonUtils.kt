@file:JvmName("CommonUtils")

package com.vim.auth.utils

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.util.*
import java.util.concurrent.atomic.AtomicLong
import kotlin.math.abs

const val START = 111_111
const val MAX = 999_999
private val counter = AtomicLong(START.toLong())

fun isValidString(vararg value: String?): Boolean {
    return Arrays.stream(value).noneMatch { str: String? -> str.isNullOrEmpty() || str.isBlank() }
}

fun generateId(): String {
    return "${abs(UUID.randomUUID().mostSignificantBits)}${(System.currentTimeMillis() + getCounterValue())}"
}

private fun getCounterValue(): Long {
    if (counter.get() >= MAX) {
        counter.set(START.toLong())
    }
    return counter.getAndIncrement()
}

fun isAnyNull(vararg values: Any): Boolean {
    return Arrays.stream(values).anyMatch { obj: Any? -> Objects.isNull(obj) }
}

fun getLogger(forClass: Class<*>): Logger = LoggerFactory.getLogger(forClass)