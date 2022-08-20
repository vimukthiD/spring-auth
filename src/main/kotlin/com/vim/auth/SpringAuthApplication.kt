package com.vim.auth

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class SpringAuthApplication

fun main(args: Array<String>) {
    runApplication<SpringAuthApplication>(*args)
}
