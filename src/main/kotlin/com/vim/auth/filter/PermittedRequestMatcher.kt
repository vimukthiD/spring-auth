package com.vim.auth.filter

import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.security.web.util.matcher.OrRequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcher
import java.util.stream.Collectors
import javax.servlet.http.HttpServletRequest
import javax.validation.constraints.NotNull

class PermittedRequestMatcher(pathsToSkip: @NotNull List<String>, processingPath: String?) : RequestMatcher {
    private val matchers: OrRequestMatcher
    private val processingMatcher: RequestMatcher

    init {
        val requestMatchers: List<RequestMatcher> = pathsToSkip.stream()
            .map { pattern: String -> AntPathRequestMatcher(pattern)  }
            .collect(Collectors.toList())
        matchers = OrRequestMatcher(requestMatchers)
        processingMatcher = AntPathRequestMatcher(processingPath)
    }

    override fun matches(request: HttpServletRequest): Boolean {
        return if (matchers.matches(request)) {
            false
        } else processingMatcher.matches(request)
    }
}