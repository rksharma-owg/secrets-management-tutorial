/*
 * ===========================================================================
 * OpenAIConfig — OpenAI API Configuration Container
 * ===========================================================================
 *
 * SECURITY PURPOSE:
 * This record holds OpenAI API configuration including the API key.
 * The API key is the most sensitive field and receives special protection:
 *
 * 1. @JsonIgnore ON API KEY — Prevents the API key from being included
 *    in any JSON serialization (API responses, logs, etc.).
 *
 * 2. IMMUTABILITY — Records cannot be modified after construction,
 *    preventing accidental key leakage through mutation.
 *
 * 3. MAX TOKENS VALIDATION — Prevents accidentally sending enormous
 *    prompts that could result in unexpected costs.
 *
 * WHY API KEYS NEED EXTRA PROTECTION:
 * - OpenAI API keys grant access to a paid service — leaked keys = real money
 * - API keys can be used to access any model, including expensive ones
 * - OpenAI keys don't expire by default — a leaked key is a permanent risk
 * - Rotate keys immediately if there's any suspicion of compromise
 *
 * COST PROTECTION:
 * Always set maxTokens to a reasonable limit to prevent:
 * - Accidental infinite loops sending thousands of requests
 * - Malicious prompts designed to maximize token usage
 * - Budget overruns from misconfigured integrations
 * ===========================================================================
 */
package com.tutorial.secrets.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;

/**
 * Immutable OpenAI API configuration retrieved from a secret provider.
 *
 * <p>The API key is annotated with {@code @JsonIgnore} to prevent it from
 * ever appearing in JSON output (API responses, logs, error messages).
 * This is a defense-in-depth measure — even if this object is accidentally
 * passed to an endpoint, the key will not be serialized.</p>
 *
 * @param apiKey      OpenAI API key (NEVER logged, serialized, or exposed)
 * @param model       the OpenAI model identifier (e.g., "gpt-4", "gpt-3.5-turbo")
 * @param organization optional OpenAI organization ID for multi-org accounts
 * @param maxTokens   maximum tokens per request (cost control)
 */
public record OpenAIConfig(
        @NotBlank(message = "OpenAI API key must not be blank")
        @JsonIgnore  // CRITICAL: Never serialize the API key under any circumstances
        String apiKey,

        @NotBlank(message = "OpenAI model must not be blank")
        String model,

        String organization,

        @Min(value = 1, message = "maxTokens must be at least 1")
        @Max(value = 128000, message = "maxTokens exceeds safe limit (128k)")
        int maxTokens
) {
    /**
     * Default maximum tokens for a single API request.
     * Set conservatively to control costs. Adjust based on your use case.
     * GPT-4 supports up to 128k tokens; GPT-3.5-turbo supports 4k or 16k.
     */
    public static final int DEFAULT_MAX_TOKENS = 4096;

    /**
     * Returns the model to use, defaulting to gpt-3.5-turbo if not set.
     * This ensures a safe default even if the secret is misconfigured.
     *
     * @return the model identifier, never null
     */
    public String effectiveModel() {
        return (model != null && !model.isBlank()) ? model : "gpt-3.5-turbo";
    }

    /**
     * Returns the effective max tokens, defaulting to DEFAULT_MAX_TOKENS if
     * not configured or set to an invalid value.
     *
     * @return max tokens, always positive and within safe bounds
     */
    public int effectiveMaxTokens() {
        return (maxTokens > 0) ? Math.min(maxTokens, 128000) : DEFAULT_MAX_TOKENS;
    }

    /**
     * Validates the configuration, checking for obvious misconfigurations.
     *
     * @throws IllegalStateException if the config appears invalid
     */
    public void validate() {
        if (apiKey == null || apiKey.isBlank()) {
            throw new IllegalStateException(
                    "OpenAI API key is missing from secret provider. " +
                    "Set 'openai-api-key' in your secret provider.");
        }

        // Check if the API key matches the well-known test key format
        // (Real keys start with "sk-" but we don't validate the full format
        // to avoid false positives if OpenAI changes their key format)
        if (apiKey.length() < 20) {
            throw new IllegalStateException(
                    "OpenAI API key appears too short and may be a placeholder. " +
                    "Real API keys start with 'sk-' and are typically 48+ characters. " +
                    "Check your secret provider configuration."
            );
        }
    }
}