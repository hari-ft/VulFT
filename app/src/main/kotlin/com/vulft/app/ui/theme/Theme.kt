package com.vulft.app.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontVariation
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import com.vulft.app.R

// ---------------------------------------------------------------- colour roles (design: "2 · Design tokens")

private val LightColors = lightColorScheme(
  primary = Color(0xFF0B5C74), onPrimary = Color(0xFFFFFFFF),
  primaryContainer = Color(0xFFC2E8F5), onPrimaryContainer = Color(0xFF002A38),
  secondary = Color(0xFF4C626B), onSecondary = Color(0xFFFFFFFF),
  secondaryContainer = Color(0xFFCFE6F0), onSecondaryContainer = Color(0xFF071E26),
  tertiary = Color(0xFF5A5C7E), onTertiary = Color(0xFFFFFFFF),
  tertiaryContainer = Color(0xFFE0E0FF), onTertiaryContainer = Color(0xFF171937),
  error = Color(0xFFB3261E), onError = Color(0xFFFFFFFF),
  errorContainer = Color(0xFFF9DEDC), onErrorContainer = Color(0xFF410E0B),
  background = Color(0xFFF7F9FB), onBackground = Color(0xFF171C1F),
  surface = Color(0xFFF7F9FB), onSurface = Color(0xFF171C1F),
  surfaceVariant = Color(0xFFDFE3E6), onSurfaceVariant = Color(0xFF40484C),
  outline = Color(0xFF70787D), outlineVariant = Color(0xFFC0C8CC),
  surfaceContainerLowest = Color(0xFFFFFFFF), surfaceContainerLow = Color(0xFFF1F4F6),
  surfaceContainer = Color(0xFFEBEEF1), surfaceContainerHigh = Color(0xFFE5E9EC),
  surfaceContainerHighest = Color(0xFFDFE3E6),
  inverseSurface = Color(0xFF2C3134), inverseOnSurface = Color(0xFFEEF1F3), inversePrimary = Color(0xFF7FD0EA),
)

private val DarkColors = darkColorScheme(
  primary = Color(0xFF7FD0EA), onPrimary = Color(0xFF003545),
  primaryContainer = Color(0xFF004D63), onPrimaryContainer = Color(0xFFC2E8F5),
  secondary = Color(0xFFB3CAD4), onSecondary = Color(0xFF1E333B),
  secondaryContainer = Color(0xFF354A52), onSecondaryContainer = Color(0xFFCFE6F0),
  tertiary = Color(0xFFC3C3EB), onTertiary = Color(0xFF2C2E4D),
  tertiaryContainer = Color(0xFF434465), onTertiaryContainer = Color(0xFFE0E0FF),
  error = Color(0xFFF2B8B5), onError = Color(0xFF601410),
  errorContainer = Color(0xFF8C1D18), onErrorContainer = Color(0xFFF9DEDC),
  background = Color(0xFF0F1417), onBackground = Color(0xFFDFE3E6),
  surface = Color(0xFF0F1417), onSurface = Color(0xFFDFE3E6),
  surfaceVariant = Color(0xFF303639), onSurfaceVariant = Color(0xFFC0C8CC),
  outline = Color(0xFF8A9296), outlineVariant = Color(0xFF40484C),
  surfaceContainerLowest = Color(0xFF0A0F11), surfaceContainerLow = Color(0xFF171C1F),
  surfaceContainer = Color(0xFF1B2023), surfaceContainerHigh = Color(0xFF252B2E),
  surfaceContainerHighest = Color(0xFF303639),
  inverseSurface = Color(0xFFDFE3E6), inverseOnSurface = Color(0xFF171C1F), inversePrimary = Color(0xFF0B5C74),
)

// ---------------------------------------------------------------- severity + status (custom, via CompositionLocal)

@Immutable data class Pair2(val fill: Color, val text: Color)

@Immutable
data class VulftColors(
  val critical: Pair2, val high: Pair2, val medium: Pair2, val low: Pair2, val none: Pair2,
  val ransomware: Pair2, val affected: Pair2, val notAffected: Pair2,
  /** Green "Updated" mark. Green is used only here (Low severity is blue), so it can't be read as a severity. */
  val updated: Pair2,
) {
  fun severity(s: String): Pair2 = when (s) { "CRITICAL" -> critical; "HIGH" -> high; "MEDIUM" -> medium; "LOW" -> low; else -> none }
}

private val LightVulft = VulftColors(
  critical = Pair2(Color(0xFFA1123F), Color.White), high = Pair2(Color(0xFFC4430A), Color.White),
  medium = Pair2(Color(0xFFF2B11B), Color(0xFF2B1D00)), low = Pair2(Color(0xFF2F6FB3), Color.White),
  none = Pair2(Color(0xFF5C666C), Color.White),
  ransomware = Pair2(Color(0xFFEBDDFF), Color(0xFF5B34A6)),
  affected = Pair2(Color(0xFFFFE7C2), Color(0xFF7A4100)),
  notAffected = Pair2(Color(0xFFE5E9EC), Color(0xFF40484C)),
  updated = Pair2(Color(0xFFD3F2DA), Color(0xFF145A2A)),
)

private val DarkVulft = VulftColors(
  critical = Pair2(Color(0xFFFF6B93), Color(0xFF3D0015)), high = Pair2(Color(0xFFFF9A62), Color(0xFF3A1400)),
  medium = Pair2(Color(0xFFF5C84B), Color(0xFF2B1D00)), low = Pair2(Color(0xFF8FBFF2), Color(0xFF062A4F)),
  none = Pair2(Color(0xFFA3ADB3), Color(0xFF1B2226)),
  ransomware = Pair2(Color(0xFF34205F), Color(0xFFCDB5FF)),
  affected = Pair2(Color(0xFF4A2E00), Color(0xFFFFC978)),
  notAffected = Pair2(Color(0xFF252B2E), Color(0xFFC0C8CC)),
  updated = Pair2(Color(0xFF16371F), Color(0xFF8EE0A2)),
)

val LocalVulftColors = staticCompositionLocalOf { DarkVulft }

object Vulft {
  val colors: VulftColors @Composable @ReadOnlyComposable get() = LocalVulftColors.current
}

// ---------------------------------------------------------------- type: Inter for UI, JetBrains Mono for identifiers

@OptIn(androidx.compose.ui.text.ExperimentalTextApi::class)
private fun inter(w: Int) = Font(R.font.inter, FontWeight(w), variationSettings = FontVariation.Settings(FontVariation.weight(w)))
@OptIn(androidx.compose.ui.text.ExperimentalTextApi::class)
private fun mono(w: Int) = Font(R.font.jetbrains_mono, FontWeight(w), variationSettings = FontVariation.Settings(FontVariation.weight(w)))

val Inter = FontFamily(inter(400), inter(500), inter(600), inter(700))
val JetBrainsMono = FontFamily(mono(400), mono(500), mono(700))

private const val TNUM = "tnum"

private fun style(size: Int, line: Int, weight: Int, family: FontFamily = Inter, tracking: Double = 0.0) =
  TextStyle(fontFamily = family, fontSize = size.sp, lineHeight = line.sp, fontWeight = FontWeight(weight), letterSpacing = tracking.em)

private val AppTypography = Typography(
  headlineSmall = style(24, 32, 600),
  titleLarge = style(22, 28, 600),
  titleMedium = style(16, 24, 600),
  titleSmall = style(14, 20, 600),
  bodyLarge = style(16, 24, 400),
  bodyMedium = style(14, 20, 400),
  bodySmall = style(12, 16, 400).copy(fontFeatureSettings = TNUM),
  labelLarge = style(14, 20, 600),
  labelMedium = style(12, 16, 700).copy(fontFeatureSettings = TNUM),
  labelSmall = style(11, 16, 700, tracking = 0.06),
)

/** Mono roles from the type sheet. */
object MonoType {
  val large = style(15, 20, 700, JetBrainsMono)   // CVE ID
  val medium = style(13, 18, 500, JetBrainsMono)  // vendor:product
  val small = style(12, 16, 500, JetBrainsMono)   // CVSS vector
}

// ---------------------------------------------------------------- shape: 4 field/menu · 8 chip · 12 card · 16 FAB · 28 dialog

private val AppShapes = Shapes(
  extraSmall = RoundedCornerShape(4.dp),
  small = RoundedCornerShape(8.dp),
  medium = RoundedCornerShape(12.dp),
  large = RoundedCornerShape(16.dp),
  extraLarge = RoundedCornerShape(28.dp),
)

@Composable
fun VulFTTheme(darkTheme: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
  CompositionLocalProvider(LocalVulftColors provides if (darkTheme) DarkVulft else LightVulft) {
    MaterialTheme(
      colorScheme = if (darkTheme) DarkColors else LightColors,
      typography = AppTypography,
      shapes = AppShapes,
      content = content,
    )
  }
}
