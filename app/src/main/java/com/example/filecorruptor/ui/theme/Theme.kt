package com.example.filecorruptor.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext

private val DarkColors = darkColorScheme(
    primary = GlitchPrimary,
    onPrimary = GlitchOnPrimary,
    primaryContainer = GlitchPrimaryContainer,
    onPrimaryContainer = GlitchOnPrimaryContainer,
    secondary = GlitchSecondary,
    onSecondary = GlitchOnSecondary,
    secondaryContainer = GlitchSecondaryContainer,
    onSecondaryContainer = GlitchOnSecondaryContainer,
    error = GlitchError,
    onError = GlitchOnError,
    background = GlitchBackgroundDark,
    onBackground = GlitchOnBackgroundDark,
    surface = GlitchSurfaceDark,
    onSurface = GlitchOnSurfaceDark,
    surfaceVariant = GlitchSurfaceVariantDark,
    onSurfaceVariant = GlitchOnSurfaceVariantDark,
)

private val LightColors = lightColorScheme(
    primary = GlitchPrimary,
    onPrimary = GlitchOnPrimary,
    primaryContainer = GlitchPrimaryContainer,
    onPrimaryContainer = GlitchOnPrimaryContainer,
    secondary = GlitchSecondary,
    onSecondary = GlitchOnSecondary,
    secondaryContainer = GlitchSecondaryContainer,
    onSecondaryContainer = GlitchOnSecondaryContainer,
    error = GlitchError,
    onError = GlitchOnError,
    background = GlitchBackgroundLight,
    onBackground = GlitchOnBackgroundLight,
    surface = GlitchSurfaceLight,
    onSurface = GlitchOnSurfaceLight,
    surfaceVariant = GlitchSurfaceVariantLight,
    onSurfaceVariant = GlitchOnSurfaceVariantLight,
)

@Composable
fun FileCorruptorTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = true,
    content: @Composable () -> Unit
) {
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        darkTheme -> DarkColors
        else -> LightColors
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = GlitchTypography,
        content = content
    )
}
